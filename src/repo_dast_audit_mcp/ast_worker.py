"""Trusted subprocess boundary for bounded Python parsing; source is only data."""
from __future__ import annotations
import json
import subprocess
import sys
from .analyzers import AdapterResult, analyze_python_ast

def excluded(reason):
    return AdapterResult("python_ast",1,"partial",0,1,reason,(),"python_ast@1")

def analyze_isolated_python(path,text,*,max_bytes=262144,max_depth=100,max_nodes=50000,max_ms=2000):
    if len(text.encode("utf-8"))>max_bytes: return excluded("AST_BYTE_LIMIT")
    request={"path":path,"text":text,"max_bytes":max_bytes,"max_depth":max_depth,"max_nodes":max_nodes}
    try:
        result=subprocess.run([sys.executable,"-I","-m",__name__],input=json.dumps(request).encode(),
            capture_output=True,timeout=max_ms/1000,check=False)
        if result.returncode or len(result.stdout)>1048576: return excluded("AST_WORKER_FAILURE")
        value=json.loads(result.stdout)
        value["findings"]=tuple(value["findings"])
        return AdapterResult(**value)
    except subprocess.TimeoutExpired:
        return excluded("AST_TIMEOUT")
    except (OSError,ValueError,KeyError,TypeError):
        return excluded("AST_WORKER_FAILURE")

def main():
    raw=sys.stdin.buffer.read(1048577)
    if len(raw)>1048576: raise ValueError("Worker input limit")
    arguments=json.loads(raw)
    try:
        value=analyze_python_ast(arguments["path"],arguments["text"],max_bytes=arguments["max_bytes"],
                                max_depth=arguments["max_depth"],max_nodes=arguments["max_nodes"]).as_dict()
        if len(value["findings"])>1000: value=excluded("AST_FINDING_LIMIT").as_dict()
    except (RecursionError,MemoryError):
        value=excluded("AST_RESOURCE_LIMIT").as_dict()
    encoded=json.dumps(value,separators=(",",":")).encode()
    if len(encoded)>1048576: encoded=json.dumps(excluded("AST_RESULT_LIMIT").as_dict()).encode()
    sys.stdout.buffer.write(encoded)
    return 0

if __name__=="__main__": raise SystemExit(main())
