#!/usr/bin/env python3
"""Noninvasive model availability check. Never sends source or findings."""
import argparse
import json
import time
import urllib.parse
import urllib.request
import urllib.error

def private_endpoint(url):
    try:
        u=urllib.parse.urlparse(url)
        return u.scheme == "http" and u.hostname in {"ollama","localhost","127.0.0.1"}
    except (TypeError, ValueError):
        return False

def check(endpoint, model, timeout=5):
    if not private_endpoint(endpoint):
        return {"ready":False, "reason":"Endpoint no autorizado; solo Ollama privado"}
    t0=time.monotonic()
    try:
        with urllib.request.urlopen(urllib.request.Request(endpoint,headers={"Accept":"application/json"}),timeout=timeout) as res:
            data=json.load(res)
        names=[str(m.get("name","")) for m in data.get("models",[]) if isinstance(m,dict)]
        return {
            "ready":model in names,
            "model":model,
            "installed_models":names,
            "latency_ms":round((time.monotonic()-t0)*1000),
            "reason":"Modelo instalado" if model in names else "Modelo no instalado; descargarlo antes de habilitar"
        }
    except (OSError, ValueError, urllib.error.URLError, TimeoutError) as error:
        return {"ready":False,"model":model,"error":type(error).__name__}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--endpoint",default="http://ollama:11434/api/tags")
    p.add_argument("--model",default="qwen3:4b")
    args=p.parse_args()
    result=check(args.endpoint,args.model)
    print(json.dumps(result,indent=2,ensure_ascii=False))
    return 0 if result.get("ready") else 2

if __name__=="__main__":
    raise SystemExit(main())
