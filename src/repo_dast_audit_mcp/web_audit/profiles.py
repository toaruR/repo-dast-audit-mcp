"""Trusted operator profiles, isolated snapshots, and secret-safe context."""
from __future__ import annotations
import hashlib
import json
import re
import shutil
from pathlib import Path
from dataclasses import dataclass
from ..config import Limits
from ..git_inventory import inventory_tracked_files, read_tracked_text

class AuditError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code

def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def redact(value, secrets=()):
    if isinstance(value, dict):
        return {key: "[REDACTED]" if re.search(r"(?i)^(?:authorization|cookie|set-cookie|password|passwd|.*(?:token|secret|api[_-]?key).*)$", key)
                else redact(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    if not isinstance(value, str):
        return value
    for secret in secrets:
        if secret:
            value = value.replace(secret, "[REDACTED]")
    value = re.sub(r"(?is)-----BEGIN (?:[A-Z ]* )?PRIVATE KEY-----.*?(?:-----END (?:[A-Z ]* )?PRIVATE KEY-----|$)", "[REDACTED PRIVATE KEY]", value)
    value = re.sub(r"""(?i)(["']?[\w-]*(?:token|secret|password|passwd|api[_-]?key)[\w-]*["']?\s*[:=]\s*)(["'])(?:\\.|[^\\\r\n"'])*["']""",
                   lambda match: match[1]+match[2]+"[REDACTED]"+match[2], value)
    value = re.sub(r"(?im)([\w-]*(?:token|secret|password|api[_-]?key)[\w-]*\s*[:=]\s*)[^\r\n]+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(bearer\s+)\S+", r"\1[REDACTED]", value)
    return value.replace("\x00", "[NUL]")

@dataclass(frozen=True)
class Profile:
    id: str
    root: Path
    image: str
    argv: tuple[str, ...]
    worker_image: str
    seccomp: Path
    port: int
    actors: dict
    resources: dict
    controls: dict
    templates: dict
    oracles: dict
    environment: dict
    fixture: bool = False
    effects: tuple[str, ...] = ("network_read",)
    login: dict | None = None
    seccomp_sha256: str = ""
    health_path: str = "/health"

    @property
    def digest(self):
        return hashlib.sha256(canonical({key: str(value) if isinstance(value, Path) else value
                                         for key, value in self.__dict__.items()})).hexdigest()

    @property
    def secrets(self):
        return tuple(str(actor.get("password", "")) for actor in self.actors.values())

    def worker_config(self, nonce: str) -> dict:
        return {"origin": f"http://127.0.0.1:{self.port}", "actors": self.actors, "resources": self.resources,
                "controls": self.controls, "templates": self.templates, "oracles": self.oracles,
                "login": self.login, "nonce": nonce, "effects": list(self.effects), "health_path": self.health_path}

def load_profiles(path: Path) -> dict[str, Profile]:
    try:
        if path.stat().st_size>262144: raise ValueError()
        document = json.loads(path.read_text(encoding="utf-8"))
        if set(document) != {"profiles"} or not isinstance(document["profiles"], list):
            raise ValueError()
        result = {}
        required = {"id", "root", "image", "argv", "worker_image", "seccomp", "port", "actors", "resources", "controls", "templates", "oracles", "environment"}
        for value in document["profiles"]:
            if not required.issubset(value) or set(value).difference(required | {"fixture", "effects", "login", "health_path"}):
                raise ValueError()
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,127}", value["id"]) or value["id"] in result:
                raise ValueError()
            if not all(re.fullmatch(r"sha256:[0-9a-f]{64}", value[key]) for key in ("image", "worker_image")):
                raise ValueError()
            if not isinstance(value["argv"], list) or not value["argv"] or len(value["argv"]) > 16 or not all(isinstance(x, str) and 0 < len(x) < 1024 for x in value["argv"]):
                raise ValueError()
            if type(value["port"]) is not int or not 1024 <= value["port"] <= 65535:
                raise ValueError()
            if not isinstance(value["actors"], dict) or not 1 <= len(value["actors"]) <= 4:
                raise ValueError()
            if not all(isinstance(value[k], dict) for k in ("resources", "controls", "templates", "oracles", "environment")):
                raise ValueError()
            if not Path(value["root"]).is_absolute() or not Path(value["seccomp"]).is_absolute():
                raise ValueError()
            if set(value.get("effects", ["network_read"])).difference({"network_read", "fixture_write"}):
                raise ValueError()
            if not 1<=len(document["profiles"])<=64: raise ValueError()
            for group,maximum in (("actors",4),("resources",200),("controls",200),("templates",100),("oracles",3)):
                if len(value[group])>maximum: raise ValueError()
                if not all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,127}",str(key)) for key in value[group]): raise ValueError()
            for actor_id,actor in value["actors"].items():
                if not isinstance(actor,dict) or set(actor).difference({"username","password","identity"}): raise ValueError()
                if actor_id!="anonymous" and set(actor)!={"username","password","identity"}: raise ValueError()
                if not all(isinstance(item,str) and 0<len(item)<=4096 for item in actor.values()): raise ValueError()
            if not all(isinstance(selector,str) and 0<len(selector)<=1024 for selector in value["controls"].values()): raise ValueError()
            if value.get("login") is not None:
                login=value["login"]
                if not isinstance(login,dict) or set(login)!={"path","username_selector","password_selector","submit_selector","identity_path","identity_field"}: raise ValueError()
                if not all(isinstance(item,str) and 0<len(item)<=1024 for item in login.values()): raise ValueError()
                if not all(re.fullmatch(r"/(?!/)[^\\\x00]*",login[key]) for key in ("path","identity_path")): raise ValueError()
            if not re.fullmatch(r"/(?!/)[^\\\x00]*",value.get("health_path","/health")): raise ValueError()
            if type(value.get("fixture",False)) is not bool: raise ValueError()
            if len(value["environment"])>64 or not all(isinstance(k,str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}",k)
                and isinstance(v,str) and len(v)<=4096 for k,v in value["environment"].items()): raise ValueError()
            for template in value["templates"].values():
                if not isinstance(template,dict) or not {"method","path","match_prefix","fields"}.issubset(template): raise ValueError()
                if set(template).difference({"method","path","match_prefix","fields","body"}): raise ValueError()
                if template["method"] not in {"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"}: raise ValueError()
                if not all(isinstance(template[key],str) and re.fullmatch(r"/(?!/)[^\\\x00]*",template[key])
                           for key in ("path","match_prefix")): raise ValueError()
                if not isinstance(template["fields"],dict) or len(template["fields"])>16: raise ValueError()
                for key,field in template["fields"].items():
                    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,127}",key) or not isinstance(field,dict): raise ValueError()
                    if not {"location","name"}.issubset(field) or set(field).difference({"location","name","type"}): raise ValueError()
                    if field["location"] not in {"path","query","json"} or field.get("type","string") not in {"string","integer"}: raise ValueError()
                    if not isinstance(field["name"],str) or not 0<len(field["name"])<=128: raise ValueError()
                if "body" in template and not isinstance(template["body"],dict): raise ValueError()
            for identifier,oracle in value["oracles"].items():
                expected={"authz_read_isolation_v1":"authz_read","xss_nonce_execution_v1":"xss_reflected_dom","business_invariant_v1":"business_invariant"}
                if identifier not in expected or not isinstance(oracle,dict) or oracle.get("category")!=expected[identifier]: raise ValueError()
                if oracle.get("template_ref") not in value["templates"]: raise ValueError()
            for resource in value["resources"].values():
                if not isinstance(resource,dict): raise ValueError()
                if resource.get("kind")=="xss_probe": continue
                if not {"id","owner","allowed"}.issubset(resource): raise ValueError()
                if resource["owner"] not in value["actors"] or not isinstance(resource["allowed"],list): raise ValueError()
                if any(actor not in value["actors"] for actor in resource["allowed"]): raise ValueError()
                if not isinstance(resource["id"],(str,int)): raise ValueError()
            policy=Path(value["seccomp"])
            if policy.stat().st_size>262144: raise ValueError()
            policy_hash=hashlib.sha256(policy.read_bytes()).hexdigest()
            value = dict(value, seccomp_sha256=policy_hash, root=Path(value["root"]).resolve(), seccomp=Path(value["seccomp"]).resolve(), argv=tuple(value["argv"]))
            if "effects" in value:
                value["effects"] = tuple(value["effects"])
            result[value["id"]] = Profile(**value)
        return result
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise AuditError("E_PROFILE", "Operator profile registry is invalid") from exc

def snapshot(root: Path, destination: Path, profile: Profile, cache: Path) -> tuple[dict, dict]:
    if root.resolve() != profile.root or root != root.resolve():
        raise AuditError("E_SCOPE", "Root is not the registered canonical project")
    inventory = inventory_tracked_files(root, cache_dir=cache, limits=Limits())
    destination.mkdir(parents=True, exist_ok=False)
    hashes, excluded = {}, []
    total = 0
    for relative in inventory.paths:
        if re.search(r"(?i)(^|/)(\.env(?:\..*)?|credentials[^/]*|id_rsa|id_ed25519)$|\.(pem|key|p12|pfx)$", relative):
            excluded.append("secret_file_excluded")
            continue
        item = read_tracked_text(inventory.target, relative, max_bytes=1_048_576)
        if item.text is None or item.status != "read":
            excluded.append(item.reason or item.status)
            continue
        payload = item.text.encode("utf-8")
        total += len(payload)
        if total > 52_428_800:
            raise AuditError("E_LIMIT", "Snapshot byte budget exceeded")
        out = destination / relative
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(payload)
        hashes[relative] = hashlib.sha256(payload).hexdigest()
    if profile.fixture:
        fixture = Path(__file__).with_name("fixture_app.py")
        shutil.copyfile(fixture, destination / "fixture_app.py")
        hashes["fixture_app.py"] = hashlib.sha256(fixture.read_bytes()).hexdigest()
    public = redact({"actors":list(profile.actors),"resources":profile.resources,"controls":profile.controls,
                     "templates":profile.templates,"oracles":profile.oracles,"effects":list(profile.effects)},profile.secrets)
    public_path = "__web_audit_profile__.json"
    if public_path in hashes: raise AuditError("E_SCOPE", "Reserved profile context filename exists in project")
    public_payload = canonical(public)
    (destination/public_path).write_bytes(public_payload)
    hashes[public_path] = hashlib.sha256(public_payload).hexdigest()
    if len(hashes)==1:
        raise AuditError("E_ENVIRONMENT", "No applicable source files in snapshot")
    digest = hashlib.sha256(canonical(hashes)).hexdigest()
    return {"profile_id": profile.id, "profile_hash": profile.digest, "snapshot_hash": digest,
            "fixture_version": "reference-v1" if profile.fixture else profile.id,
            "source_files": len(hashes), "excluded_reasons": sorted(set(excluded))}, hashes
