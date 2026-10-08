"""Private, authenticated job generations; no caller-supplied filesystem paths."""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import secrets
import shutil
import time
import uuid
from pathlib import Path
from ..render import escape_markdown
from .profiles import AuditError, canonical

def atomic(path: Path, payload: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary=path.with_name(path.name+".tmp")
    with temporary.open("wb") as stream:
        stream.write(payload); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary,path)

def protect_cache(root: Path):
    """Restrict the server-owned cache before loading credentials or evidence."""
    import subprocess
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink(): raise AuditError("E_STORAGE", "Cache cannot be a symbolic link")
    if os.name != "nt":
        root.chmod(0o700)
        return
    import csv
    try:
        identity=subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],capture_output=True,
                                check=True,timeout=5,text=True).stdout
        sid=next(csv.reader(identity.splitlines()))[1]
        result=subprocess.run(["icacls",str(root),"/inheritance:r","/grant:r","*"+sid+":(OI)(CI)F"],
                              capture_output=True,check=False,timeout=10)
        if result.returncode: raise ValueError()
    except (OSError,ValueError,IndexError,subprocess.SubprocessError) as exc:
        raise AuditError("E_STORAGE", "Private cache permissions could not be established") from exc

class CacheLock:
    def __init__(self, root: Path):
        root.mkdir(parents=True, exist_ok=True)
        self.stream=(root/".server.lock").open("a+b")
        try:
            if os.name=="nt":
                import msvcrt
                self.stream.seek(0); self.stream.write(b"0"); self.stream.flush(); self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError as exc:
            self.stream.close()
            raise AuditError("E_BUSY","Cache is already in use") from exc

    def close(self):
        if self.stream.closed: return
        if os.name=="nt":
            import msvcrt
            self.stream.seek(0); msvcrt.locking(self.stream.fileno(),msvcrt.LK_UNLCK,1)
        self.stream.close()

class JobStore:
    def __init__(self, cache: Path):
        self.root=cache/"web-audits"; self.root.mkdir(parents=True,exist_ok=True)
        key_path=self.root/".audit-key"
        if key_path.exists(): self.key=key_path.read_bytes()
        else:
            self.key=secrets.token_bytes(32); atomic(key_path,self.key)
        if len(self.key)!=32: raise AuditError("E_STORAGE","Invalid cache key")

    def admit(self):
        """Prune only authenticated, cleaned records older than seven days."""
        now=time.time()
        for directory in [p for p in self.root.iterdir() if p.is_dir()]:
            if directory.is_symlink() or (hasattr(directory,"is_junction") and directory.is_junction()):
                raise AuditError("E_STORAGE","Cache directory cannot be a link")
            if directory.resolve().parent!=self.root.resolve():
                raise AuditError("E_STORAGE","Cache directory escaped its root")
            job=self.load(directory.name)
            if now-(directory/"current.json").stat().st_mtime<=7*86400: continue
            if job["state"] not in {"completed","partial","cancelled","interrupted","failed"} or job["cleanup"]["status"]!="verified": continue
            for current,children,files in os.walk(directory,followlinks=False):
                for name in children+files:
                    item=Path(current)/name
                    if item.is_symlink() or (hasattr(item,"is_junction") and item.is_junction()):
                        raise AuditError("E_STORAGE","Cache contains a filesystem link")
            shutil.rmtree(directory)
        if sum(p.is_dir() for p in self.root.iterdir())>=100:
            raise AuditError("E_LIMIT","Retained audit record limit reached")

    def directory(self, identifier: str):
        try: uuid.UUID(identifier)
        except (ValueError,TypeError,AttributeError) as exc: raise AuditError("E_NOT_FOUND","Unknown audit") from exc
        return self.root/identifier

    def save(self, job: dict, report: dict):
        directory=self.directory(job["audit_id"])
        generation=directory/"generations"/str(job["revision"])
        if generation.exists(): raise AuditError("E_STORAGE","Generation already exists")
        rendered=canonical(report)
        if len(rendered)>2_097_152: raise AuditError("E_LIMIT","Report byte budget exceeded")
        escaped=escape_markdown
        lines=["# Web security audit", "", f"Audit: {escaped(report['audit_id'])}",
               f"State: {escaped(report['state'])}", f"Revision: {report['revision']}",
               f"Profile: {escaped(job['profile_id'])}", f"Cleanup: {escaped(report['cleanup']['status'])}",
               "", "## Cases", "", "| Case | Category | Status | Reason |", "| --- | --- | --- | --- |"]
        for case in report["cases"]:
            lines.append("| "+" | ".join(escaped(case[key] or "pending") for key in ("case_id","category","status","reason"))+" |")
        lines+=["", "## Confirmed findings"]
        for finding in report["findings"]:
            lines+=["", f"### {escaped(finding['category'])}: {escaped(finding['finding_id'])}", "",
                    f"Severity: {escaped(finding['severity'])}; oracle: {escaped(finding['oracle_id'])}",
                    f"Actor: {escaped(finding['actor_id'])}; resource: {escaped(finding['resource_ref'])}",
                    f"Expected: {escaped(finding['expected'])}", f"Observed: {escaped(finding['observed'])}",
                    f"Source localized: {finding['source_localized']}",
                    "Source refs: "+", ".join(escaped(ref) for ref in finding["source_refs"]), "", "Replay steps:"]
            for index,step in enumerate(finding["replay_steps"],1):
                encoded=json.dumps(step,ensure_ascii=False,sort_keys=True)
                text=encoded if len(encoded)<=8192 else encoded[:8192]+" [truncated; full step in report.json]"
                lines.append(f"{index}. {escaped(text)}")
            lines+=["", "Evidence (artifact / SHA-256 / role):"]
            for evidence in finding["evidence"]:
                lines.append("- "+escaped(evidence["artifact_id"])+" / "+escaped(evidence["sha256"])+" / "+escaped(evidence["role"]))
        lines+=["","## Coverage","",escaped(json.dumps(report["coverage"],ensure_ascii=False,sort_keys=True)),
                "", "## Uncertainty",""]+["- "+escaped(x) for x in report["uncertainties"]]
        markdown=("\n".join(lines)+"\n").encode()
        if len(markdown)>1_572_864:
            markdown=markdown[:1_572_600].decode("utf-8",errors="ignore").encode()+b"\n\n[Markdown truncated; see canonical report.json.]\n"
        reserve=104_857_600 if job["state"] in {"finalizing","completed","partial","cancelled","interrupted","failed"} else 94_371_840
        if job["budget"]["artifact_bytes"]+2*(len(rendered)+len(markdown))>reserve:
            raise AuditError("E_LIMIT","Report storage budget exceeded")
        atomic(generation/"report.json",rendered); atomic(generation/"report.md",markdown)
        job["budget"]["artifact_bytes"]+=len(rendered)+len(markdown)
        job["report_refs"]={"report_version":2,"revision":job["revision"],
            "json_artifact_id":self.artifact(job,"report_json","application/json",rendered),
            "markdown_artifact_id":self.artifact(job,"report_markdown","text/plain",markdown)}
        raw=canonical(job)
        if len(raw)>16_777_216: raise AuditError("E_LIMIT","Job state byte budget exceeded")
        signature=hmac.new(self.key,raw,hashlib.sha256).hexdigest()
        atomic(directory/"current.json",canonical({"job":job,"signature":signature}))

    def load(self, identifier: str):
        path=self.directory(identifier)/"current.json"
        if not path.is_file(): raise AuditError("E_NOT_FOUND","Unknown audit")
        try:
            if path.stat().st_size>16_777_216: raise ValueError()
            signed=json.loads(path.read_bytes())
            job=signed["job"]
            if job["audit_id"]!=identifier or not hmac.compare_digest(signed["signature"],hmac.new(self.key,canonical(job),hashlib.sha256).hexdigest()):
                raise ValueError()
            return job
        except (OSError,KeyError,ValueError,TypeError) as exc:
            raise AuditError("E_STORAGE","Audit generation is invalid") from exc

    def artifact(self, job: dict, kind: str, mime: str, payload: bytes):
        maximum=104_857_600 if kind in ("report_json","report_markdown") else 94_371_840
        if job["budget"]["artifact_bytes"]+len(payload)>maximum:
            raise AuditError("E_LIMIT","Artifact storage budget exceeded")
        identifier=str(uuid.uuid4())
        atomic(self.directory(job["audit_id"])/"artifacts"/identifier,payload)
        job["budget"]["artifact_bytes"]+=len(payload)
        job["artifacts"][identifier]={"kind":kind,"mime_type":mime,"sha256":hashlib.sha256(payload).hexdigest(),"byte_length":len(payload)}
        return identifier

    def charge_source(self,job,size):
        path=self.directory(job["audit_id"])/"source_reads.json"
        value={"kind":"source_budget","audit_id":job["audit_id"],"bytes":0}
        if path.exists():
            try:
                if path.stat().st_size>1024: raise ValueError()
                signed=json.loads(path.read_bytes()); value=signed["value"]
                if value["audit_id"]!=job["audit_id"] or value["kind"]!="source_budget" or type(value["bytes"]) is not int:
                    raise ValueError()
                if not hmac.compare_digest(signed["signature"],hmac.new(self.key,canonical(value),hashlib.sha256).hexdigest()):
                    raise ValueError()
            except (ValueError,KeyError,TypeError) as exc:
                raise AuditError("E_STORAGE","Source read budget authentication failed") from exc
        if value["bytes"]+size>1048576: raise AuditError("E_LIMIT","Source disclosure budget exceeded")
        value["bytes"]+=size
        signature=hmac.new(self.key,canonical(value),hashlib.sha256).hexdigest()
        atomic(path,canonical({"value":value,"signature":signature}))
        return value["bytes"]

    def read_artifact(self, job: dict, identifier: str):
        item=job["artifacts"].get(identifier)
        if not item: raise AuditError("E_NOT_FOUND","Unknown artifact")
        data=(self.directory(job["audit_id"])/"artifacts"/identifier).read_bytes()
        if hashlib.sha256(data).hexdigest()!=item["sha256"]: raise AuditError("E_STORAGE","Artifact hash mismatch")
        return item,data

    def cursor(self, value: dict):
        import base64
        raw=canonical(value)
        return base64.urlsafe_b64encode(raw+hmac.new(self.key,raw,hashlib.sha256).digest()).decode()

    def parse_cursor(self, cursor: str):
        import base64
        try:
            raw=base64.urlsafe_b64decode(cursor.encode()); data,signature=raw[:-32],raw[-32:]
            if not hmac.compare_digest(signature,hmac.new(self.key,data,hashlib.sha256).digest()): raise ValueError()
            return json.loads(data)
        except (ValueError,TypeError) as exc: raise AuditError("E_SCHEMA","Invalid cursor") from exc
