import json
import asyncio
from types import SimpleNamespace

from src.mcp_server import mcp

ps_line = json.dumps({"Names": "webapp_web_1", "ID": "abcd1234"}) + "\n"
inspect_obj = [{
    "Id": "abcd1234",
    "Name": "/webapp_web_1",
    "Config": {"Image": "web:1.2.3", "Labels": {"com.docker.compose.service": "web"}},
    "HostConfig": {"NetworkMode": "bridge"},
    "NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}},
    "Mounts": []
}]

def fake_run(args, capture_output=True, text=True, check=True):
    if args[:3] == ["docker", "ps", "-a"] or args[:4] == ["docker", "ps", "-a", "--format"]:
        return SimpleNamespace(stdout=ps_line, returncode=0, stderr='')
    if args[0] == "docker" and args[1] == "inspect":
        return SimpleNamespace(stdout=json.dumps(inspect_obj), returncode=0, stderr='')
    raise RuntimeError("Unexpected docker command: %r"%args)

import subprocess as _sub
_sub.run = fake_run

with open('inventory.json','w') as f:
    json.dump({"hosts":{},"stacks":{"webapp":{"stack_name":"webapp","host":"node-1","path":"/srv/webapp","services":["web"]}}},f)

tool = next((t for t in mcp.tools if t.name == "get_stack_network_info"), None)
print('tool', tool)
res = asyncio.get_event_loop().run_until_complete(tool.function(host='node-1', stack_name='webapp'))
print('res=', res)
