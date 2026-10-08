"""Strict validation of the shipped, bounded schema vocabulary; no target code execution."""
from __future__ import annotations
import copy
import json
import re
import uuid
from pathlib import Path
from typing import Any

SCHEMA = json.loads(Path(__file__).with_name("contract.schema.json").read_text(encoding="utf-8"))
DEFS = SCHEMA["$defs"]
TOOL_NAMES = tuple(item["$ref"].split("/")[-1].removesuffix("Request") for item in DEFS["Request"]["oneOf"])

class ContractError(ValueError):
    pass

def matches(schema: dict, value: Any) -> bool:
    if "$ref" in schema:
        return matches(DEFS[schema["$ref"].split("/")[-1]], value)
    if "oneOf" in schema and sum(matches(item, value) for item in schema["oneOf"]) != 1:
        return False
    if "anyOf" in schema and not any(matches(item, value) for item in schema["anyOf"]):
        return False
    if "const" in schema and (type(value) is not type(schema["const"]) or value != schema["const"]):
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    types = {"object": type(value) is dict, "array": type(value) is list, "integer": type(value) is int,
             "string": type(value) is str, "boolean": type(value) is bool, "null": value is None}
    if "type" in schema and not types.get(schema["type"], False):
        return False
    if isinstance(value, dict):
        if any(key not in value for key in schema.get("required", ())):
            return False
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and set(value).difference(properties):
            return False
        if any(not matches(properties[key], item) for key, item in value.items() if key in properties):
            return False
    if isinstance(value, list):
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", len(value)):
            return False
        if "items" in schema and not all(matches(schema["items"], item) for item in value):
            return False
    if isinstance(value, str):
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", len(value)):
            return False
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            return False
        if schema.get("format") == "uuid":
            try:
                if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}",value): return False
                uuid.UUID(value)
            except (ValueError, TypeError):
                return False
    if type(value) is int and not schema.get("minimum", value) <= value <= schema.get("maximum", value):
        return False
    return True


def normalize(schema, value):
    if "$ref" in schema: return normalize(DEFS[schema["$ref"].split("/")[-1]],value)
    if schema.get("format")=="uuid": return str(uuid.UUID(value))
    for keyword in ("oneOf","anyOf"):
        if keyword in schema:
            chosen=next(item for item in schema[keyword] if matches(item,value))
            return normalize(chosen,value)
    if isinstance(value,dict):
        return {key:normalize(schema.get("properties",{}).get(key,{}),item) for key,item in value.items()}
    if isinstance(value,list):
        return [normalize(schema.get("items",{}),item) for item in value]
    return value

def validate_input(name: str, arguments: Any) -> dict:
    if name not in TOOL_NAMES or not matches(DEFS[name + "Input"], arguments):
        raise ContractError("invalid web audit arguments")
    return normalize(DEFS[name + "Input"],copy.deepcopy(arguments))

def expand(schema: dict) -> dict:
    if "$ref" in schema:
        return expand(DEFS[schema["$ref"].split("/")[-1]])
    return {key: [expand(x) if isinstance(x, dict) else x for x in value] if isinstance(value, list)
            else expand(value) if isinstance(value, dict) else value for key, value in schema.items()}

def definitions() -> list[dict]:
    return [{"name": name, "description": "Profile-scoped web audit: " + name,
             "inputSchema": expand(DEFS[name + "Input"]),
             "outputSchema": {"oneOf": [expand(DEFS[name + "Success"]), expand(DEFS["ErrorResult"])]}}
            for name in TOOL_NAMES]
