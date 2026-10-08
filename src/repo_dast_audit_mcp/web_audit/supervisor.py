"""Client-driven hypotheses with server-owned execution, evidence and cleanup."""
from __future__ import annotations
import copy
import hashlib
import json
import logging
import threading
import time
import uuid
from pathlib import Path
from .contracts import DEFS, TOOL_NAMES, ContractError, matches, validate_input
from .profiles import AuditError, canonical, load_profiles, redact, snapshot
from .runtime import DockerRuntime
from .storage import JobStore

TERMINAL={"completed","partial","cancelled","interrupted","failed"}
LIMITS={"job_wall_ms":1_200_000,"action_ms":15_000,"case_ms":120_000,"actions":200,"http_requests":1000,
        "response_bytes":1048576,"total_bytes":52428800,"cases":30,"steps_per_case":20,
        "source_bytes":1048576,"artifact_bytes":104857600}

class WebAuditService:
    def __init__(self, cache: Path, profiles_path: Path, runtime_factory=DockerRuntime):
        self.store=JobStore(cache)
        self.profiles=load_profiles(profiles_path)
        self.runtime_factory=runtime_factory
        self.lock=threading.RLock()
        self.jobs={}; self.runtimes={}; self.active=None; self.blocked=False
        self.clock={}; self.last_activity={}
        self.shutdown = threading.Event()
        for directory in self.store.root.iterdir():
            if directory.is_dir():
                try:
                    job=self.store.load(directory.name)
                    self.jobs[job["audit_id"]]=job
                    if job["state"] not in TERMINAL or job["cleanup"]["status"]!="verified":
                        job["state"]="finalizing"
                        DockerRuntime.recover(job["audit_id"])
                        for action in job["actions"].values():
                            if action["status"] in ("prepared","dispatched"): action["status"]="outcome_unknown"
                        job["state"]="interrupted"; job["runtime"]["status"]="stopped"
                        job["cleanup"]={"status":"verified","resource_manifest_hash":None,"reason":"PROCESS_RESTART"}
                        job["uncertainties"].append("process_restart_actions_not_resumed")
                        self._save(job)
                except AuditError:
                    self.blocked=True
        threading.Thread(target=self._watch,daemon=True).start()

    def _report(self, job):
        cases=list(job["cases"].values())
        views=[{key:case[key] for key in ("case_id","category","status","reason","evidence")} for case in cases]
        coverage={"eligible_cases":sum(case["plan"]["oracle_id"] is not None for case in cases),
                  **{key:sum(case["status"]==key for case in cases) for key in ("confirmed","rejected","candidate","inconclusive","skipped")},
                  "uninspected_reasons":list(job["uncertainties"])}
        return {"report_version":2,"audit_id":job["audit_id"],"revision":job["revision"],"state":job["state"],
                "scope":job["scope"],"runtime":job["runtime"],"coverage":coverage,"cases":views,
                "findings":list(job["findings"]),"uncertainties":list(job["uncertainties"]),"limits":dict(LIMITS),"cleanup":job["cleanup"]}

    def _save(self, job):
        job["revision"]+=1
        if job["audit_id"] in self.clock:
            job["budget"]["elapsed_ms"]=int((time.monotonic()-self.clock[job["audit_id"]])*1000)
        self.store.save(job,self._report(job))

    def _job(self, identifier):
        job=self.jobs.get(identifier)
        if job is None:
            job=self.store.load(identifier); self.jobs[identifier]=job
        # Authenticate on each read, even when an in-memory projection exists.
        self.store.load(identifier)
        return job

    def _success(self, name, job, result):
        value={"ok":True,"audit_id":job["audit_id"],"revision":job["revision"],"state":job["state"],"operation":name,"result":result}
        if not matches(DEFS[name+"Success"],value):
            raise AuditError("E_STORAGE","Internal result contract failed")
        value=copy.deepcopy(value)
        return {"content":[{"type":"text","text":json.dumps(value,ensure_ascii=False,separators=(",",":"))}],"structuredContent":value}

    def handle(self, name, arguments, cancelled=None):
        try:
            arguments=validate_input(name,arguments)
            if cancelled and cancelled(): raise AuditError("E_CAPABILITY","Request cancelled before admission")
            with self.lock:
                if name=="start_web_audit": return self._start(name,arguments)
                job=self._job(arguments["audit_id"])
                self.last_activity[job["audit_id"]]=time.monotonic()
                if name=="get_web_audit": return self._get(name,job,arguments)
                if name=="get_web_artifact": return self._artifact(name,job,arguments)
                if name=="get_web_source": return self._source(name,job,arguments)
                if name=="cancel_web_audit":
                    if job["state"] not in TERMINAL and job["state"]!="finalizing":
                        job["state"]="finalizing"; job["end_reason"]="cancelled"; self._save(job)
                        threading.Thread(target=self._finish,args=(job["audit_id"],"cancelled"),daemon=True).start()
                    return self._success(name,job,{"requested":True,"cleanup":job["cleanup"]})
                if name in ("web_action","verify_web_case") and arguments["client_action_id"] in job["idempotency"]:
                    return self._dispatch(name,job,arguments)
                if arguments["expected_revision"]!=job["revision"]: raise AuditError("E_REVISION","Revision is stale")
                if job["state"] in TERMINAL|{"finalizing","queued","provisioning"}: raise AuditError("E_BUSY","Audit is not ready")
                if name in ("web_action","verify_web_case"):
                    return self._dispatch(name,job,arguments)
                if any(x["status"] in ("prepared","dispatched") for x in job["actions"].values()):
                    raise AuditError("E_BUSY","An action is active")
                if name=="propose_web_case": return self._propose(name,job,arguments)
                if name=="finish_web_audit":
                    job["state"]="finalizing"; job["end_reason"]=arguments["reason"]; self._save(job)
                    threading.Thread(target=self._finish,args=(job["audit_id"],None),daemon=True).start()
                    return self._success(name,job,{"requested":True,"cleanup":job["cleanup"]})
                raise AuditError("E_SCHEMA","Unknown audit operation")
        except ContractError:
            error=AuditError("E_SCHEMA","Invalid web audit arguments")
        except AuditError as exc:
            error=exc
            if exc.code=="E_STORAGE": self.blocked=True
        except (OSError,ValueError,KeyError,TypeError):
            error=AuditError("E_STORAGE","Audit operation failed")
        identifier=arguments.get("audit_id") if isinstance(arguments,dict) else None
        value={"ok":False,"code":error.code,"message":str(error)[:256],"retryable":error.code in ("E_BUSY","E_REVISION"),"audit_id":identifier}
        return {"isError":True,"content":[{"type":"text","text":json.dumps(value)}],"structuredContent":value}

    def _start(self,name,args):
        if self.blocked: raise AuditError("E_SUPERVISION","Cleanup or recovery requires attention")
        if self.active: raise AuditError("E_BUSY","A web audit is already active")
        self.store.admit()
        profile=self.profiles.get(args["profile_id"])
        if not profile: raise AuditError("E_PROFILE","Unknown registered profile")
        root=Path(args["root"])
        if root!=profile.root or root.resolve()!=profile.root: raise AuditError("E_SCOPE","Root does not match the registered project")
        if "static_scan_id" in args:
            raise AuditError("E_CAPABILITY","Static snapshot identity is not available; omit static_scan_id")
        identifier=str(uuid.uuid4())
        job={"audit_id":identifier,"revision":0,"state":"queued","profile_id":profile.id,
             "scope":{"profile_id":profile.id,"profile_hash":profile.digest,"snapshot_hash":None,
                      "fixture_version":"reference-v1" if profile.fixture else profile.id,"source_files":None,"excluded_reasons":[]},
             "runtime":{"adapter_id":"docker_loopback_v1","image_digest":profile.image,"status":"preparing","authentication":"not_started"},
             "cleanup":{"status":"pending","resource_manifest_hash":None,"reason":None},
             "budget":{"actions":0,"http_requests":0,"bytes_read":0,"elapsed_ms":0,"source_bytes":0,"artifact_bytes":0,"stopped_by":None},
             "cases":{},"actions":{},"idempotency":{},"observations":[],"observation_meta":{},"artifacts":{},
             "sources":{},"uncertainties":["service_workers_blocked","websockets_not_tested","only_selected_oracles_tested"],
             "findings":[],"report_refs":None,"end_reason":None}
        if profile.fixture: job["uncertainties"].append("reference_fixture_only_not_project_findings")
        self.jobs[identifier]=job; self.active=identifier
        self.clock[identifier]=self.last_activity[identifier]=time.monotonic()
        self._save(job)
        threading.Thread(target=self._prepare,args=(identifier,),daemon=True).start()
        return self._success(name,job,{"admitted":True})

    def _prepare(self,identifier):
        try:
            with self.lock:
                job=self.jobs[identifier]; profile=self.profiles[job["profile_id"]]
                if job["state"] in TERMINAL|{"finalizing"}: return
                job["state"]="provisioning"; self._save(job)
            directory=self.store.directory(identifier)/"snapshot"
            scope,hashes=snapshot(profile.root,directory,profile,self.store.root.parent)
            runtime=self.runtime_factory(profile,directory,identifier)
            runtime.deadline=self.clock[identifier]+1200
            with self.lock:
                if job["state"]=="finalizing": return
                self.runtimes[identifier]=runtime
                job["scope"]=scope
                job["sources"]={}
                for path in sorted(hashes,key=lambda value:value!="__web_audit_profile__.json"):
                    raw=(directory/path).read_bytes()
                    public=redact(raw.decode("utf-8"),profile.secrets).encode("utf-8")
                    excerpt=public[:16384].decode("utf-8",errors="ignore").encode("utf-8")
                    artifact=self.store.artifact(job,"source","text/plain",excerpt)
                    reference="source_"+hashlib.sha256(path.encode()).hexdigest()[:16]
                    job["sources"][reference]={"relative_path":path,"sha256":hashes[path],
                                              "artifact_id":artifact,"truncated":len(public)>16384}
                self._save(job)
            runtime.start()
            with self.lock:
                if job["state"]=="finalizing":
                    runtime.stop(); return
                job["runtime"].update(status="ready",authentication="available")
                job["state"]="ready"; self._stats(job,runtime); self._save(job)
        except AuditError as exc:
            with self.lock:
                if job["state"] in TERMINAL|{"finalizing"}: return
                logging.getLogger(__name__).warning("Audit provisioning failed (%s): %s",exc.code,redact(str(exc),profile.secrets))
                job["uncertainties"].append("provisioning_"+exc.code)
            self._finish(identifier,"failed")
        except Exception:
            self._finish(identifier,"failed")

    def _stats(self,job,runtime):
        for key in ("http_requests","bytes_read"):
            job["budget"][key]=max(job["budget"][key],int(runtime.stats.get(key,0)))

    def _dispatch(self,name,job,args):
        signature=hashlib.sha256(canonical({key:value for key,value in args.items() if key!="expected_revision"})).hexdigest()
        prior=job["idempotency"].get(args["client_action_id"])
        if prior:
            if prior["hash"]!=signature: raise AuditError("E_SCHEMA","Action ID was reused with a different input")
            action=job["actions"][prior["action_id"]]
            result={"action":action}
            if name=="verify_web_case": result["case_id"]=args["case_id"]
            return self._success(name,job,result)
        if any(x["status"] in ("prepared","dispatched") for x in job["actions"].values()): raise AuditError("E_BUSY","An action is active")
        if job["budget"]["actions"]>=200: raise AuditError("E_LIMIT","Action budget exceeded")
        profile=self.profiles[job["profile_id"]]
        if name=="web_action":
            if args["action"]["actor_id"] not in profile.actors: raise AuditError("E_AUTH","Unknown actor")
        else:
            case=job["cases"].get(args["case_id"])
            if not case: raise AuditError("E_NOT_FOUND","Unknown case")
            if case["status"]!="candidate": raise AuditError("E_CAPABILITY","Case is already resolved")
            if not case["plan"]["oracle_id"]: raise AuditError("E_CAPABILITY","Candidate has no deterministic oracle")
        action_id=str(uuid.uuid4())
        action={"action_id":action_id,"client_action_id":args["client_action_id"],"status":"prepared",
                "observation_ids":[],"artifact_ids":[],"reason":None}
        job["actions"][action_id]=action
        job["idempotency"][args["client_action_id"]]={"hash":signature,"action_id":action_id}
        job["budget"]["actions"]+=1; job["state"]="testing" if name=="verify_web_case" else "exploring"
        self._save(job)
        threading.Thread(target=self._execute,args=(job["audit_id"],action_id,name,copy.deepcopy(args)),daemon=True).start()
        result={"action":action}
        if name=="verify_web_case": result["case_id"]=args["case_id"]
        return self._success(name,job,result)

    def _propose(self,name,job,args):
        plan=args["case"]; profile=self.profiles[job["profile_id"]]
        if len(canonical(plan))>65536: raise AuditError("E_LIMIT","Case plan byte budget exceeded")
        if len(job["cases"])>=30: raise AuditError("E_LIMIT","Case budget exceeded")
        if plan["actor_id"] not in profile.actors: raise AuditError("E_AUTH","Unknown actor")
        if set(plan["effects"]).difference(profile.effects): raise AuditError("E_CAPABILITY","Case effect is not permitted")
        if not all(ref in job["observation_meta"] for ref in plan["baseline_observation_ids"]): raise AuditError("E_CAPABILITY","Baseline was not observed")
        if not all(ref in job["sources"] for ref in plan["source_refs"]): raise AuditError("E_CAPABILITY","Unknown source reference")
        if plan["oracle_id"]:
            oracle=profile.oracles.get(plan["oracle_id"])
            if not oracle or oracle["category"]!=plan["category"]: raise AuditError("E_CAPABILITY","Oracle and category do not match")
            if len(plan["steps"])!=1 or plan["steps"][0]["kind"]!="replay_request":
                raise AuditError("E_CAPABILITY","This oracle supports one registered request step")
            step=plan["steps"][0]
            if step["template_ref"]!=oracle["template_ref"] or step["actor_id"]!=plan["actor_id"]:
                raise AuditError("E_CAPABILITY","Step does not match the registered oracle")
            template=profile.templates[step["template_ref"]]
            for mutation in step["mutations"]:
                if mutation["field_ref"] not in template["fields"]: raise AuditError("E_CAPABILITY","Unknown mutable field")
                if isinstance(mutation["value"],dict) and mutation["value"]["fixture_ref"] not in profile.resources:
                    raise AuditError("E_CAPABILITY","Unknown fixture resource")
        identifier=str(uuid.uuid4())
        case={"case_id":identifier,"category":plan["category"],"status":"candidate","reason":None,"evidence":[],"plan":plan}
        job["cases"][identifier]=case; self._save(job)
        return self._success(name,job,{"case":{k:case[k] for k in ("case_id","category","status","reason","evidence")}})

    def _execute(self,identifier,action_id,name,args):
        try:
            with self.lock:
                job=self.jobs[identifier]; action=job["actions"][action_id]; runtime=self.runtimes[identifier]
                if job["state"] in TERMINAL|{"finalizing"}: return
                action["status"]="dispatched"; self._save(job)
            if name=="web_action":
                outcome=runtime.call("action",args["action"])
                with self.lock:
                    if job["state"] in TERMINAL|{"finalizing"}: return
                    observation=outcome["observation"]; observation["observation_id"]=str(uuid.uuid4())
                    observation["source_refs"]=list(job["sources"])[:20]
                    observation=redact(observation,self.profiles[job["profile_id"]].secrets)
                    artifact=self.store.artifact(job,"dom","application/json",canonical(observation))
                    observation["artifact_ids"].append(artifact)
                    action["artifact_ids"].append(artifact); action["observation_ids"].append(observation["observation_id"])
                    job["observation_meta"][observation["observation_id"]]={"actor":observation["actor_id"],"artifact_id":artifact}
                    job["observations"]=(job["observations"]+[observation])[-2:]
                    if "network" in outcome:
                        action["artifact_ids"].append(self.store.artifact(job,"network","application/json",canonical(redact(outcome["network"]))))
            else:
                case=job["cases"][args["case_id"]]
                results=[]
                runtime.deadline=min(self.clock[identifier]+1200,time.monotonic()+120)
                for repeat in range(2):
                    if job["state"]=="finalizing": raise AuditError("E_UNKNOWN_ACTION","Verification was interrupted")
                    runtime.start()
                    outcome=runtime.call("verify",case["plan"],timeout=45)
                    results.append(outcome["status"])
                    with self.lock:
                        if job["state"] in TERMINAL|{"finalizing"}: return
                        for evidence in outcome["evidence"]:
                            payload=canonical(redact(evidence["value"],self.profiles[job["profile_id"]].secrets))
                            artifact=self.store.artifact(job,"network","application/json",payload)
                            role="repeat" if repeat else evidence["role"]
                            case["evidence"].append({"artifact_id":artifact,"sha256":hashlib.sha256(payload).hexdigest(),"role":role})
                            action["artifact_ids"].append(artifact)
                        self._stats(job,runtime)
                        self._save(job)
                with self.lock:
                    if job["state"] in TERMINAL|{"finalizing"}: return
                    case["status"]=results[0] if len(set(results))==1 else "inconclusive"
                    case["reason"]=outcome["reason"] if len(set(results))==1 else "replay_disagreed"
                    if case["status"]=="confirmed":
                        from datetime import datetime,timezone
                        job["findings"].append({"finding_id":str(uuid.uuid4()),"case_id":case["case_id"],"category":case["category"],
                            "status":"confirmed","severity":self.profiles[job["profile_id"]].oracles[case["plan"]["oracle_id"]].get("severity","unknown"),"oracle_id":case["plan"]["oracle_id"],"oracle_version":1,
                            "profile_hash":job["scope"]["profile_hash"],"snapshot_hash":job["scope"]["snapshot_hash"],
                            "actor_id":case["plan"]["actor_id"],"resource_ref":case["plan"]["resource_ref"],"fixture_version":job["scope"]["fixture_version"],
                            "expected":"Registered profile invariant holds","observed":case["reason"],
                            "conditions":["synthetic fixture","two independent fresh replays"],"source_refs":case["plan"]["source_refs"],
                            "evidence":case["evidence"],"replay_steps":case["plan"]["steps"],"source_localized":False,
                            "verified_at":datetime.now(timezone.utc).isoformat()})
            runtime.deadline=self.clock[identifier]+1200
            with self.lock:
                if job["state"] in TERMINAL|{"finalizing"}: return
                if action["status"]=="dispatched": action["status"]="completed"
                self._stats(job,runtime); self.last_activity[identifier]=time.monotonic(); self._save(job)
        except AuditError as exc:
            logging.getLogger(__name__).warning("Audit action failed (%s): %s",exc.code,redact(str(exc),self.profiles[job["profile_id"]].secrets))
            with self.lock:
                if job["state"] in TERMINAL|{"finalizing"}: return
                action["status"]="outcome_unknown" if exc.code in ("E_UNKNOWN_ACTION","E_ENVIRONMENT") else "failed"
                action["reason"]=exc.code
                if name=="verify_web_case":
                    case=job["cases"][args["case_id"]]; case["status"]="inconclusive"; case["reason"]=exc.code
                job["uncertainties"].append("action_"+exc.code)
                self._stats(job,runtime)
                try: self._save(job)
                except AuditError: self.blocked=True
            if exc.code in ("E_LIMIT","E_UNKNOWN_ACTION","E_ENVIRONMENT","E_SUPERVISION"):
                if exc.code=="E_SUPERVISION": self.blocked=True
                self._finish(identifier,"failed" if exc.code=="E_SUPERVISION" else "partial")
        except Exception:
            with self.lock:
                action["status"]="outcome_unknown"; action["reason"]="E_STORAGE"
            self._finish(identifier,"failed")

    def _get(self,name,job,args):
        report=self._report(job)
        if args.get("cursor"):
            cursor=self.store.parse_cursor(args["cursor"])
            if cursor.get("audit")!=job["audit_id"] or cursor.get("revision")!=job["revision"]: raise AuditError("E_REVISION","Read cursor is stale; request a fresh summary")
            offset=cursor["offset"]
        else: offset=0
        actions=list(job["actions"].values())
        cases=report["cases"]
        next_offset=offset+10
        next_cursor=self.store.cursor({"audit":job["audit_id"],"revision":job["revision"],"offset":next_offset}) if next_offset<max(len(actions),len(cases)) else None
        result={"scope":job["scope"],"runtime":job["runtime"],"coverage":report["coverage"],"budget":job["budget"],"cleanup":job["cleanup"],
                "actions":actions[offset:offset+10],"cases":cases[offset:offset+10],"observations":job["observations"],
                "report":job["report_refs"],"next_cursor":next_cursor}
        return self._success(name,job,result)

    def _source(self,name,job,args):
        source=job["sources"].get(args["source_ref"])
        if not source: raise AuditError("E_NOT_FOUND","Unknown source reference")
        item,payload=self.store.read_artifact(job,source["artifact_id"])
        consumed=self.store.charge_source(job,len(payload))
        if job["state"] not in TERMINAL:
            job["budget"]["source_bytes"]=consumed
            self._save(job)
        excerpt=payload.decode("utf-8")
        return self._success(name,job,{"source_ref":args["source_ref"],"relative_path":source["relative_path"],"sha256":source["sha256"],
            "start_line":1,"end_line":max(1,len(excerpt.splitlines())),"excerpt":excerpt,"truncated":source["truncated"]})

    def _artifact(self,name,job,args):
        item,payload=self.store.read_artifact(job,args["artifact_id"])
        offset=0
        if args.get("cursor"):
            cursor=self.store.parse_cursor(args["cursor"])
            if cursor.get("artifact")!=args["artifact_id"]: raise AuditError("E_SCHEMA","Artifact cursor mismatch")
            offset=cursor["offset"]
        end=min(offset+32768,len(payload))
        chunk=payload[offset:end]
        # Choose UTF-8 boundaries; cursor offset refers to the immutable byte stream.
        decoded=chunk.decode("utf-8",errors="ignore")
        consumed=len(decoded.encode("utf-8"))
        if not consumed and chunk: raise AuditError("E_STORAGE","Artifact text could not be decoded")
        end=offset+consumed
        result={"artifact_id":args["artifact_id"],**item,"redacted":True,"excerpt":decoded,
                "truncated":end<len(payload),"image_attached":False,
                "next_cursor":self.store.cursor({"artifact":args["artifact_id"],"offset":end}) if end<len(payload) else None}
        return self._success(name,job,result)

    def _finish(self,identifier,terminal):
        with self.lock:
            job=self.jobs[identifier]
            if job["state"] in TERMINAL: return
            job["state"]="finalizing"; self._save(job)
        try:
            runtime=self.runtimes.get(identifier)
            if runtime: runtime.stop()
            with self.lock:
                if runtime: self._stats(job,runtime)
                for action in job["actions"].values():
                    if action["status"] in ("prepared","dispatched"):
                        action["status"]="outcome_unknown"; action["reason"]="interrupted"
                for case in job["cases"].values():
                    if case["status"]=="candidate" and terminal is not None: case["status"]="inconclusive"; case["reason"]="session_ended"
                resolved=bool(job["cases"]) and all(c["status"] in ("confirmed","rejected") for c in job["cases"].values())
                job["state"]=terminal or ("completed" if resolved and all(a["status"]=="completed" for a in job["actions"].values()) else "partial")
                job["runtime"]["status"]="stopped"
                job["cleanup"]={"status":"verified","resource_manifest_hash":hashlib.sha256(canonical({"audit_id":identifier,"containers":["web-audit-"+identifier+"-target","web-audit-"+identifier+"-worker","web-audit-"+identifier+"-seed"],"volumes":["web-audit-"+identifier+"-snapshot"]})).hexdigest(),"reason":None}
                self._save(job)
                if self.active==identifier: self.active=None
        except AuditError:
            with self.lock:
                self.blocked=True; job["state"]="failed"
                job["cleanup"]={"status":"failed","resource_manifest_hash":None,"reason":"cleanup_failed"}
                try:self._save(job)
                except AuditError:pass

    def _watch(self):
        while not self.shutdown.wait(0.5):
            identifier=self.active
            if identifier:
                with self.lock:
                    job=self.jobs[identifier]
                    if job["state"] in TERMINAL|{"finalizing"}: continue
                    elapsed=time.monotonic()-self.clock[identifier]
                    idle=time.monotonic()-self.last_activity[identifier]
                    pending=any(a["status"] in ("prepared","dispatched") for a in job["actions"].values())
                    reason="job_deadline" if elapsed>1200 else "provisioning_deadline" if job["state"]=="provisioning" and elapsed>180 else "client_idle" if not pending and idle>180 else None
                    if not reason: continue
                    job["budget"]["stopped_by"]=reason
                self._finish(identifier,"partial")

    def close(self):
        self.shutdown.set()
        if self.active: self._finish(self.active,"cancelled")
