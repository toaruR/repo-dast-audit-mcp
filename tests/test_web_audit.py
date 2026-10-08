"""Contract, lifecycle and tamper tests for the browser audit supervisor."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid
from repository_vulnerability_report_mcp.protocol import JsonRpcProtocol
from repository_vulnerability_report_mcp.web_audit.contracts import ContractError, DEFS, SCHEMA, matches, validate_input
from repository_vulnerability_report_mcp.web_audit.profiles import AuditError, canonical, redact
from repository_vulnerability_report_mcp.web_audit.setup import reference_profile
from repository_vulnerability_report_mcp.web_audit.storage import CacheLock
from repository_vulnerability_report_mcp.web_audit.supervisor import WebAuditService

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    Draft202012Validator = None


def validate_document(name, value):
    if Draft202012Validator is not None:
        schema={"$schema": SCHEMA["$schema"], "$defs": DEFS, "$ref": "#/$defs/"+name}
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)


class FakeRuntime:
    mode="confirmed"
    reason="invariant"
    def __init__(self,profile,snapshot,audit):
        self.stats={"http_requests":0,"bytes_read":0}
        self.stopped=threading.Event(); self.entered=threading.Event(); self.starts=0; self.verifications=0
    def start(self):
        if self.stopped.is_set(): raise AuditError("E_UNKNOWN_ACTION","Cancelled")
        self.starts+=1
    def stop(self): self.stopped.set(); return True
    def call(self,method,args,timeout=15):
        self.entered.set()
        if self.mode=="blocked":
            self.stopped.wait(5)
            raise AuditError("E_UNKNOWN_ACTION","Unknown outcome")
        self.stats["http_requests"]+=3; self.stats["bytes_read"]+=100
        if method=="verify":
            self.verifications+=1
            status="confirmed" if self.mode!="disagree" or self.verifications==1 else "rejected"
            return {"status":status,"reason":self.reason,"evidence":[
                {"role":"control","value":{"ok":True,"password":"fixture-only"}},
                {"role":"attack","value":{"ok":False}}]}
        return {"observation":{"actor_id":args["actor_id"],"identity_verified":True,"path":"/orders",
            "dom_excerpt":"untrusted page text","element_refs":[],"control_refs":["order"],
            "request_refs":[],"template_refs":["order_read"],"source_refs":[],"artifact_ids":[],"truncated":False}}

class WebContractTests(unittest.TestCase):
    @unittest.skipUnless(Draft202012Validator is not None, "Install the test extra for independent schema validation")
    def test_full_draft_schema_and_documented_examples(self):
        Draft202012Validator.check_schema(SCHEMA)
        path=Path(__file__).resolve().parents[1]/"docs/plans/web-security-audit-examples.json"
        for example in json.loads(path.read_text(encoding="utf-8")):
            name=example["tool"]+"Input" if "tool" in example else "Success" if example["ok"] else "ErrorResult"
            validate_document(name, example.get("arguments", example))

    def test_tools_are_opt_in(self):
        request={"jsonrpc":"2.0","id":1,"method":"tools/list"}
        self.assertEqual(len(JsonRpcProtocol().handle_message(request)["result"]["tools"]),3)
        self.assertEqual(len(JsonRpcProtocol(web_audit_enabled=True).handle_message(request)["result"]["tools"]),12)
    def test_arbitrary_execution_and_destinations_rejected(self):
        good={"audit_id":str(uuid.uuid4()),"expected_revision":1,"client_action_id":str(uuid.uuid4()),
              "action":{"kind":"observe","actor_id":"user_a"}}
        validate_input("web_action",good)
        invalid=[]
        for action in ({"kind":"evaluate","actor_id":"user_a","script":"x"},
                       {"kind":"navigate","actor_id":"user_a","path":"https://example.com"},
                       {"kind":"navigate","actor_id":"user_a","path":"//example.com"},
                       {"kind":"navigate","actor_id":"user_a","path":"/\\example.com"}):
            invalid.append(dict(good,action=action))
        invalid.append(dict(good,expected_revision=True))
        invalid.append(dict(good,command="anything"))
        for item in invalid:
            with self.subTest(item=item),self.assertRaises(ContractError): validate_input("web_action",item)
    def test_redaction(self):
        data=redact({"Authorization":"Bearer abc","nested":{"password":"hunter2","message":"key=hunter2"}},
                    ("hunter2",))
        self.assertNotIn("hunter2",json.dumps(data)); self.assertNotIn("Bearer abc",json.dumps(data))
    def test_single_process_cache_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            lock=CacheLock(Path(directory))
            try:
                with self.assertRaises(AuditError): CacheLock(Path(directory))
            finally: lock.close()
            CacheLock(Path(directory)).close()

    def test_quoted_json_and_api_key_secrets_are_masked(self):
        value=redact({"apiKey":"private-value","message":'api_key = "private-value"',"access_token":"private-token"})
        self.assertNotIn("private-value",json.dumps(value))
        self.assertNotIn("private-token",json.dumps(value))

    def test_noncanonical_uuid_alias_is_normalized(self):
        identifier=str(uuid.uuid4())
        value=validate_input("get_web_audit",{"audit_id":identifier.upper()})
        self.assertEqual(value["audit_id"],identifier)
        with self.assertRaises(ContractError): validate_input("get_web_audit",{"audit_id":identifier.replace("-","")})

    def test_ambiguous_or_deep_wire_json_rejected_before_dispatch(self):
        protocol=JsonRpcProtocol()
        for frame in (b'{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}',
                      b'{"jsonrpc":"2.0","id":NaN,"method":"ping"}',
                      b'['*2000+b'0'+b']'*2000):
            self.assertEqual(protocol.handle_frame(frame)["error"]["code"],-32700)

class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.base=Path(self.temp.name).resolve(); self.root=self.base/"project"; self.root.mkdir()
        (self.root/"app.py").write_text("print('synthetic')\n")
        subprocess.run(["git","init",str(self.root)],capture_output=True,check=True)
        subprocess.run(["git","-C",str(self.root),"add","app.py"],capture_output=True,check=True)
        self.registry=self.base/"profiles.json"
        (self.base/"seccomp.json").write_text("{}")
        profile=reference_profile(self.root,"sha256:"+"a"*64,"sha256:"+"b"*64,self.base/"seccomp.json")
        profile["fixture"]=False
        self.registry.write_text(json.dumps({"profiles":[profile]}))
        FakeRuntime.mode="confirmed"; FakeRuntime.reason="invariant"
        self.service=WebAuditService(self.base/"cache",self.registry,FakeRuntime)
    def tearDown(self):
        self.service.close(); self.temp.cleanup()
    def call(self,name,args):
        value=self.service.handle(name,args)["structuredContent"]
        validate_document(name+"Success" if value["ok"] else "ErrorResult",value)
        return value
    def ready(self):
        result=self.call("start_web_audit",{"root":str(self.root),"profile_id":"fixture_vulnerable"})
        self.assertTrue(result["ok"],result)
        audit=result["audit_id"]
        return self.wait(audit,lambda x:x["state"]=="ready")
    def wait(self,audit,predicate):
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            value=self.call("get_web_audit",{"audit_id":audit})
            self.assertTrue(value["ok"],value)
            if predicate(value): return value
            time.sleep(.01)
        self.fail(value)
    def observe(self,value):
        identifier=value["audit_id"]; action_id=str(uuid.uuid4())
        args={"audit_id":identifier,"expected_revision":value["revision"],"client_action_id":action_id,
              "action":{"kind":"observe","actor_id":"user_a"}}
        receipt=self.call("web_action",args)
        self.assertTrue(receipt["ok"],receipt)
        value=self.wait(identifier,lambda x:bool(x["result"]["observations"]))
        return value,args,receipt
    def plan(self,observation):
        return {"category":"authz_read","hypothesis":"B's object should be denied to A","actor_id":"user_a",
            "resource_ref":"order_b","oracle_id":"authz_read_isolation_v1",
            "baseline_observation_ids":[observation["observation_id"]],"source_refs":[],
            "steps":[{"kind":"replay_request","actor_id":"user_a","template_ref":"order_read",
                "mutations":[{"field_ref":"order_id","value":{"fixture_ref":"order_b"}}]}],"effects":["network_read"]}
    def propose(self,value):
        return self.call("propose_web_case",{"audit_id":value["audit_id"],"expected_revision":value["revision"],
                                            "case":self.plan(value["result"]["observations"][-1])})
    def test_scope_registry_required(self):
        bad=self.call("start_web_audit",{"root":str(self.base),"profile_id":"fixture_vulnerable"})
        self.assertEqual(bad["code"],"E_SCOPE")
        bad=self.call("start_web_audit",{"root":str(self.root),"profile_id":"unknown"})
        self.assertEqual(bad["code"],"E_PROFILE")
    def test_duplicate_action_and_stale_revision(self):
        value,args,receipt=self.observe(self.ready())
        duplicate=self.call("web_action",args)
        self.assertEqual(duplicate["result"]["action"]["action_id"],receipt["result"]["action"]["action_id"])
        self.assertEqual(len(self.service.jobs[value["audit_id"]]["actions"]),1)
        conflict=copy.deepcopy(args); conflict["action"]["actor_id"]="user_b"
        self.assertEqual(self.call("web_action",conflict)["code"],"E_SCHEMA")
        stale=self.call("propose_web_case",{"audit_id":value["audit_id"],"expected_revision":1,
                                          "case":self.plan(value["result"]["observations"][-1])})
        self.assertEqual(stale["code"],"E_REVISION")
    def test_unobserved_baseline_and_unknown_field_denied(self):
        value,_,_=self.observe(self.ready()); plan=self.plan(value["result"]["observations"][-1])
        plan["baseline_observation_ids"]=[str(uuid.uuid4())]
        args={"audit_id":value["audit_id"],"expected_revision":value["revision"],"case":plan}
        self.assertEqual(self.call("propose_web_case",args)["code"],"E_CAPABILITY")
        plan=self.plan(value["result"]["observations"][-1]); plan["steps"][0]["mutations"][0]["field_ref"]="secret"
        args["case"]=plan
        self.assertEqual(self.call("propose_web_case",args)["code"],"E_CAPABILITY")
    def test_independent_replays_disagreement_not_confirmed(self):
        FakeRuntime.mode="disagree"
        value,_,_=self.observe(self.ready()); proposed=self.propose(value)
        self.assertTrue(proposed["ok"],proposed)
        audit=value["audit_id"]; case_id=proposed["result"]["case"]["case_id"]
        result=self.call("verify_web_case",{"audit_id":audit,"expected_revision":proposed["revision"],
                    "client_action_id":str(uuid.uuid4()),"case_id":case_id})
        self.assertTrue(result["ok"],result)
        value=self.wait(audit,lambda x:bool(x["result"]["cases"]) and x["result"]["cases"][0]["status"]!="candidate")
        self.assertEqual(value["result"]["cases"][0]["status"],"inconclusive")
        self.assertEqual(self.service.jobs[audit]["findings"],[])
        self.assertEqual(self.service.runtimes[audit].starts,3)
        self.assertEqual(len(value["result"]["cases"][0]["evidence"]),4)
    def test_report_revision_state_and_secret_free_evidence(self):
        value,_,_=self.observe(self.ready())
        plan=self.plan(value["result"]["observations"][-1])
        plan["hypothesis"]="<script>alert(1)</script> [follow](https://example.com)"
        FakeRuntime.reason=plan["hypothesis"]
        proposed=self.call("propose_web_case",{"audit_id":value["audit_id"],"expected_revision":value["revision"],"case":plan})
        audit=value["audit_id"]; case_id=proposed["result"]["case"]["case_id"]
        self.call("verify_web_case",{"audit_id":audit,"expected_revision":proposed["revision"],
                  "client_action_id":str(uuid.uuid4()),"case_id":case_id})
        value=self.wait(audit,lambda x:x["result"]["cases"][0]["status"]=="confirmed")
        refs=value["result"]["report"]
        report=self.call("get_web_artifact",{"audit_id":audit,"artifact_id":refs["json_artifact_id"]})["result"]
        document=json.loads(report["excerpt"])
        validate_document("DynamicReport",document)
        markdown=self.call("get_web_artifact",{"audit_id":audit,"artifact_id":refs["markdown_artifact_id"]})["result"]["excerpt"]
        self.assertIn("Confirmed findings",markdown)
        self.assertIn(document["findings"][0]["evidence"][0]["sha256"],markdown)
        self.assertIn("&lt;script&gt;",markdown)
        self.assertNotIn("<script>",markdown)
        self.assertNotIn("[follow](https://example.com)",markdown)

        self.assertTrue(matches(DEFS["DynamicReport"],document),document)
        self.assertEqual(document["revision"],value["revision"]); self.assertEqual(document["state"],value["state"])
        evidence=value["result"]["cases"][0]["evidence"][0]
        artifact=self.call("get_web_artifact",{"audit_id":audit,"artifact_id":evidence["artifact_id"]})["result"]
        self.assertNotIn("fixture-only",artifact["excerpt"])
        self.assertEqual(hashlib.sha256(artifact["excerpt"].encode()).hexdigest(),evidence["sha256"])
    def test_cancel_unknown_outcome_no_resend_or_late_revision(self):
        value=self.ready(); audit=value["audit_id"]; runtime=self.service.runtimes[audit]
        FakeRuntime.mode="blocked"
        args={"audit_id":audit,"expected_revision":value["revision"],"client_action_id":str(uuid.uuid4()),
              "action":{"kind":"observe","actor_id":"user_a"}}
        receipt=self.call("web_action",args); self.assertTrue(runtime.entered.wait(2))
        self.call("cancel_web_audit",{"audit_id":audit})
        final=self.wait(audit,lambda x:x["state"]=="cancelled")
        self.assertEqual(final["result"]["actions"][0]["status"],"outcome_unknown")
        time.sleep(.1)
        self.assertEqual(self.call("get_web_audit",{"audit_id":audit})["revision"],final["revision"])
        duplicate=self.call("web_action",args)
        self.assertEqual(duplicate["result"]["action"]["status"],"outcome_unknown")
    def test_state_and_artifact_tamper_detected(self):
        value,args,receipt=self.observe(self.ready()); audit=value["audit_id"]
        artifact=value["result"]["observations"][0]["artifact_ids"][0]
        (self.service.store.directory(audit)/"artifacts"/artifact).write_bytes(b"changed")
        self.assertEqual(self.call("get_web_artifact",{"audit_id":audit,"artifact_id":artifact})["code"],"E_STORAGE")
        path=self.service.store.directory(audit)/"current.json"
        state=json.loads(path.read_bytes()); state["job"]["state"]="completed"; path.write_bytes(canonical(state))
        self.assertEqual(self.call("get_web_audit",{"audit_id":audit})["code"],"E_STORAGE")
    def test_restart_pending_action_is_unknown(self):
        value=self.ready(); audit=value["audit_id"]; job=self.service.jobs[audit]
        self.service.shutdown.set()
        action_id=str(uuid.uuid4())
        with self.service.lock:
            job["state"]="exploring"; job["actions"][action_id]={"action_id":action_id,"client_action_id":str(uuid.uuid4()),
                "status":"dispatched","observation_ids":[],"artifact_ids":[],"reason":None}
            self.service._save(job)
        with patch("repository_vulnerability_report_mcp.web_audit.supervisor.DockerRuntime.recover",return_value=True):
            second=WebAuditService(self.base/"cache",self.registry,FakeRuntime)
        self.service=second
        recovered=self.call("get_web_audit",{"audit_id":audit})
        self.assertEqual(recovered["state"],"interrupted")
        self.assertEqual(recovered["result"]["actions"][0]["status"],"outcome_unknown")

    def test_terminal_source_is_immutable_redacted_without_current_profile(self):
        (self.root/"app.py").write_text("PASSWORD = 'fixture-only'\n")
        value=self.ready(); audit=value["audit_id"]
        source=next(ref for ref,item in self.service.jobs[audit]["sources"].items() if item["relative_path"]=="app.py")
        self.call("finish_web_audit",{"audit_id":audit,"expected_revision":value["revision"],"reason":"client_finished"})
        final=self.wait(audit,lambda x:x["state"]=="partial")
        self.service.profiles.clear()
        result=self.call("get_web_source",{"audit_id":audit,"source_ref":source})
        self.assertTrue(result["ok"],result)
        self.assertNotIn("fixture-only",result["result"]["excerpt"])
        self.assertEqual(result["revision"],final["revision"])
        ledger=self.service.store.directory(audit)/"source_reads.json"
        signed=json.loads(ledger.read_bytes()); signed["value"]["bytes"]=0; ledger.write_bytes(canonical(signed))
        self.assertEqual(self.call("get_web_source",{"audit_id":audit,"source_ref":source})["code"],"E_STORAGE")

if __name__=="__main__": unittest.main()
