"""Opt-in real Docker/Chromium acceptance tests (never target an external service)."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from repository_vulnerability_report_mcp.web_audit.profiles import load_profiles, snapshot
from repository_vulnerability_report_mcp.web_audit.runtime import DockerRuntime
from test_web_audit import validate_document

@unittest.skipUnless(os.environ.get("WEB_AUDIT_INTEGRATION")=="1","Requires isolated Docker browser runtime")
class BrowserIntegrationTests(unittest.TestCase):
    def test_paired_fixture_through_stdio(self):
        registry=Path(os.environ["REPOSITORY_WEB_PROFILES"]).resolve()
        profiles=load_profiles(registry)
        with tempfile.TemporaryDirectory(prefix="web-audit-") as temp:
            env=dict(os.environ,REPOSITORY_WEB_AUDIT="1",LOCALAPPDATA=temp)
            process=subprocess.Popen([sys.executable,"-m","repository_vulnerability_report_mcp.server"],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding="utf-8",env=env)
            counter=0
            def call(name,args):
                nonlocal counter
                counter+=1
                process.stdin.write(json.dumps({"jsonrpc":"2.0","id":counter,"method":"tools/call","params":{"name":name,"arguments":args}})+"\n")
                process.stdin.flush()
                line=process.stdout.readline()
                if not line: raise AssertionError("Server ended: "+process.stderr.read())
                result=json.loads(line)
                self.assertNotIn("error",result,result)
                value=result["result"]["structuredContent"]
                self.assertTrue(value["ok"],value)
                validate_document(name+"Success" if value["ok"] else "ErrorResult",value)
                return value
            def wait(audit,predicate,timeout=180):
                deadline=time.monotonic()+timeout
                while time.monotonic()<deadline:
                    value=call("get_web_audit",{"audit_id":audit})
                    if predicate(value): return value
                    if value["state"] in ("failed","interrupted","cancelled"):
                        raise AssertionError(value)
                    time.sleep(.1)
                raise AssertionError("Timed out: "+str(value))
            try:
                process.stdin.write(json.dumps({"jsonrpc":"2.0","id":0,"method":"tools/list"})+"\n"); process.stdin.flush()
                tools=json.loads(process.stdout.readline())["result"]["tools"]
                self.assertEqual(len(tools),12)
                for profile_id,expected in (("fixture_vulnerable","confirmed"),("fixture_patched","rejected")):
                    profile=profiles[profile_id]
                    value=call("start_web_audit",{"root":str(profile.root),"profile_id":profile_id})
                    audit=value["audit_id"]
                    value=wait(audit,lambda x:x["state"]=="ready")
                    inspect=json.loads(subprocess.check_output(["docker","inspect","web-audit-"+audit+"-target"],text=True))[0]
                    self.assertEqual(inspect["HostConfig"]["NetworkMode"],"none")
                    self.assertEqual(inspect["Config"]["User"],"1000:1000")
                    self.assertFalse(inspect["HostConfig"]["Privileged"])
                    self.assertEqual(len(inspect["Mounts"]),1)
                    self.assertEqual(inspect["Mounts"][0]["Type"],"volume")
                    self.assertFalse(inspect["Mounts"][0]["RW"])
                    worker_name="web-audit-"+audit+"-worker"
                    worker=json.loads(subprocess.check_output(["docker","inspect",worker_name],text=True))[0]
                    self.assertEqual(worker["HostConfig"]["NetworkMode"],"container:"+inspect["Id"])
                    self.assertTrue(worker["HostConfig"]["ReadonlyRootfs"])
                    self.assertFalse(worker["HostConfig"]["Privileged"])
                    self.assertEqual(worker["Mounts"],[])
                    self.assertEqual(worker["HostConfig"]["CapDrop"],["ALL"])
                    script="const n=require('node:net'),o=require('node:os');const s=n.connect(80,'203.0.113.1');s.setTimeout(1000);s.on('connect',()=>{process.exit(1)});s.on('timeout',()=>{process.exit(2)});s.on('error',e=>{console.log(JSON.stringify({interfaces:Object.keys(o.networkInterfaces()),code:e.code}));s.destroy()})"
                    isolation=json.loads(subprocess.check_output(["docker","exec",worker_name,"node","-e",script],text=True,timeout=5))
                    self.assertEqual(isolation["interfaces"],["lo"])
                    self.assertEqual(isolation["code"],"ENETUNREACH")

                    observe_id=str(uuid.uuid4())
                    receipt=call("web_action",{"audit_id":audit,"expected_revision":value["revision"],
                        "client_action_id":observe_id,"action":{"kind":"observe","actor_id":"user_a"}})
                    action=receipt["result"]["action"]["action_id"]
                    value=wait(audit,lambda x:any(a["action_id"]==action and a["status"] not in ("prepared","dispatched") for a in x["result"]["actions"]))
                    self.assertEqual(next(a for a in value["result"]["actions"] if a["action_id"]==action)["status"],"completed",value)
                    observation=value["result"]["observations"][-1]
                    self.assertTrue(observation["identity_verified"])
                    # An identical action ID reuses the action even with its original revision.
                    duplicate=call("web_action",{"audit_id":audit,"expected_revision":receipt["revision"]-1,
                        "client_action_id":observe_id,"action":{"kind":"observe","actor_id":"user_a"}})
                    self.assertEqual(duplicate["result"]["action"]["action_id"],action)
                    cases=[
                        ("authz_read","authz_read_isolation_v1","order_b","order_read","order_id",{"fixture_ref":"order_b"},["network_read"]),
                        ("xss_reflected_dom","xss_nonce_execution_v1",None,"search","query",{"fixture_ref":"xss_probe"},["network_read"]),
                        ("business_invariant","business_invariant_v1",None,"discount","percent","150",["network_read","fixture_write"]),
                    ]
                    for index,(category,oracle,resource,template,field,mutation,effects) in enumerate(cases):
                        value=call("get_web_audit",{"audit_id":audit})
                        plan={"category":category,"hypothesis":"Registered invariant may be violated","actor_id":"user_a",
                            "resource_ref":resource,"oracle_id":oracle,"baseline_observation_ids":[observation["observation_id"]],
                            "source_refs":[],"steps":[{"kind":"replay_request","actor_id":"user_a","template_ref":template,
                                                     "mutations":[{"field_ref":field,"value":mutation}]}],"effects":effects}
                        proposed=call("propose_web_case",{"audit_id":audit,"expected_revision":value["revision"],"case":plan})
                        case_id=proposed["result"]["case"]["case_id"]
                        verified=call("verify_web_case",{"audit_id":audit,"expected_revision":proposed["revision"],
                                    "client_action_id":str(uuid.uuid4()),"case_id":case_id})
                        action_id=verified["result"]["action"]["action_id"]
                        value=wait(audit,lambda x:any(a["action_id"]==action_id and a["status"] not in ("prepared","dispatched")
                                                      for a in x["result"]["actions"]))
                        case=next(c for c in value["result"]["cases"] if c["case_id"]==case_id)
                        self.assertEqual(case["status"],expected,{"case":case,"budget":value["result"]["budget"]})
                        self.assertEqual(len(case["evidence"]),4)
                        artifact=call("get_web_artifact",{"audit_id":audit,"artifact_id":case["evidence"][0]["artifact_id"]})["result"]
                        self.assertEqual(hashlib.sha256(artifact["excerpt"].encode()).hexdigest(),artifact["sha256"])
                        self.assertNotIn("fixture-only",artifact["excerpt"])
                        print(profile_id,category,case["status"],flush=True)
                    value=call("get_web_audit",{"audit_id":audit})
                    call("finish_web_audit",{"audit_id":audit,"expected_revision":value["revision"],"reason":"client_finished"})
                    final=wait(audit,lambda x:x["state"]=="completed")
                    self.assertEqual(final["result"]["cleanup"]["status"],"verified")
                    residual=subprocess.check_output(["docker","ps","-a","--filter","label=repository-web-audit="+audit,"-q"],text=True)
                    self.assertEqual(residual.strip(),"")
            finally:
                process.stdin.close()
                try: process.wait(timeout=45)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
                diagnostics=process.stderr.read()
                if diagnostics: print(diagnostics,file=sys.stderr,flush=True)
                for stream in (process.stdout,process.stderr): stream.close()


    def test_registered_repository_and_crash_recovery(self):
        from repository_vulnerability_report_mcp.web_audit.setup import reference_profile
        registry=Path(os.environ["REPOSITORY_WEB_PROFILES"]).resolve()
        reference=load_profiles(registry)["fixture_vulnerable"]
        with tempfile.TemporaryDirectory(prefix="web-audit-project-") as temporary:
            base=Path(temporary).resolve(); root=base/"project"; root.mkdir()
            source=Path(__file__).resolve().parents[1]/"src/repository_vulnerability_report_mcp/web_audit/fixture_app.py"
            payload=source.read_bytes(); (root/"service.py").write_bytes(payload)
            subprocess.run(["git","init",str(root)],capture_output=True,check=True)
            subprocess.run(["git","-C",str(root),"add","service.py"],capture_output=True,check=True)
            profile=reference_profile(root,reference.image,reference.worker_image,reference.seccomp)
            profile.update(id="local_project",fixture=False,argv=["python3","-B","/app/service.py"])
            operator_registry=base/"profiles.json"; operator_registry.write_text(json.dumps({"profiles":[profile]}))
            env=dict(os.environ,REPOSITORY_WEB_AUDIT="1",REPOSITORY_WEB_PROFILES=str(operator_registry),LOCALAPPDATA=str(base/"cache"))
            process=None; counter=0
            def launch():
                return subprocess.Popen([sys.executable,"-m","repository_vulnerability_report_mcp.server"],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding="utf-8",env=env)
            def call(name,args):
                nonlocal counter
                counter+=1
                process.stdin.write(json.dumps({"jsonrpc":"2.0","id":counter,"method":"tools/call","params":{"name":name,"arguments":args}})+"\n")
                process.stdin.flush()
                line=process.stdout.readline()
                self.assertTrue(line,"Server stopped: "+(process.stderr.read() if process.poll() is not None else ""))
                wire=json.loads(line); self.assertNotIn("error",wire,wire)
                value=wire["result"]["structuredContent"]; self.assertTrue(value["ok"],value)
                return value
            def wait(audit,predicate):
                deadline=time.monotonic()+180
                while time.monotonic()<deadline:
                    value=call("get_web_audit",{"audit_id":audit})
                    if predicate(value): return value
                    self.assertNotIn(value["state"],("failed","partial","cancelled"),value)
                    time.sleep(.1)
                self.fail(value)
            def stop():
                if process and process.poll() is None:
                    process.stdin.close()
                    try: process.wait(timeout=45)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()
                if process:
                    diagnostics=process.stderr.read()
                    if diagnostics: print(diagnostics,file=sys.stderr)
                    for stream in (process.stdin,process.stdout,process.stderr):
                        if not stream.closed: stream.close()
            try:
                process=launch()
                admitted=call("start_web_audit",{"root":str(root),"profile_id":"local_project"})
                audit=admitted["audit_id"]; value=wait(audit,lambda x:x["state"]=="ready")
                call("web_action",{"audit_id":audit,"expected_revision":value["revision"],"client_action_id":str(uuid.uuid4()),
                                  "action":{"kind":"observe","actor_id":"user_a"}})
                value=wait(audit,lambda x:bool(x["result"]["observations"]))
                observation=value["result"]["observations"][-1]
                source_ref=next(ref for ref in observation["source_refs"] if call("get_web_source",{"audit_id":audit,"source_ref":ref})["result"]["relative_path"]=="service.py")
                actual=call("get_web_source",{"audit_id":audit,"source_ref":source_ref})["result"]
                self.assertEqual(actual["sha256"],hashlib.sha256(payload).hexdigest())
                value=call("get_web_audit",{"audit_id":audit})
                plan={"category":"authz_read","hypothesis":"A cannot read B's synthetic order","actor_id":"user_a",
                    "resource_ref":"order_b","oracle_id":"authz_read_isolation_v1","baseline_observation_ids":[observation["observation_id"]],
                    "source_refs":[source_ref],"steps":[{"kind":"replay_request","actor_id":"user_a","template_ref":"order_read",
                        "mutations":[{"field_ref":"order_id","value":{"fixture_ref":"order_b"}}]}],"effects":["network_read"]}
                proposed=call("propose_web_case",{"audit_id":audit,"expected_revision":value["revision"],"case":plan})
                case_id=proposed["result"]["case"]["case_id"]
                call("verify_web_case",{"audit_id":audit,"expected_revision":proposed["revision"],"case_id":case_id,"client_action_id":str(uuid.uuid4())})
                value=wait(audit,lambda x:x["result"]["cases"][0]["status"]!="candidate" and all(a["status"] not in ("prepared","dispatched") for a in x["result"]["actions"]))
                self.assertEqual(value["result"]["cases"][0]["status"],"confirmed",value)
                self.assertNotIn("reference_fixture_only_not_project_findings",value["result"]["coverage"]["uninspected_reasons"])
                call("finish_web_audit",{"audit_id":audit,"expected_revision":value["revision"],"reason":"plan_complete"})
                final=wait(audit,lambda x:x["state"]=="completed")
                report=call("get_web_artifact",{"audit_id":audit,"artifact_id":final["result"]["report"]["json_artifact_id"]})
                finding=json.loads(report["result"]["excerpt"])["findings"][0]
                self.assertEqual(finding["source_refs"],[source_ref])
                self.assertFalse(finding["source_localized"])
                print("registered_project authz_read confirmed; tracked source hash verified",flush=True)
                # Abruptly terminate only our MCP server while a typed action is pending.
                admitted=call("start_web_audit",{"root":str(root),"profile_id":"local_project"})
                crash_audit=admitted["audit_id"]; ready=wait(crash_audit,lambda x:x["state"]=="ready")
                receipt=call("web_action",{"audit_id":crash_audit,"expected_revision":ready["revision"],"client_action_id":str(uuid.uuid4()),
                                         "action":{"kind":"navigate","actor_id":"user_a","path":"/orders"}})
                process.kill(); process.wait(timeout=10); stop()
                process=launch()
                recovered=call("get_web_audit",{"audit_id":crash_audit})
                self.assertEqual(recovered["state"],"interrupted")
                self.assertEqual(recovered["result"]["cleanup"]["status"],"verified")
                self.assertEqual(recovered["result"]["actions"][0]["status"],"outcome_unknown")
                for command in (["docker","ps","-a","--filter","label=repository-web-audit="+crash_audit,"-q"],
                                ["docker","volume","ls","--filter","label=repository-web-audit="+crash_audit,"-q"]):
                    self.assertEqual(subprocess.check_output(command,text=True).strip(),"")
                print("process_restart: unknown outcome preserved; containers and volume removed",flush=True)
            finally: stop()

if __name__=="__main__": unittest.main()
