"""Run one tool server over streamable HTTP: python -m agentguard.tools files --port 8001"""

import argparse

import uvicorn
from mcp.server.mcpserver import MCPServer

from agentguard.tools import SERVERS

parser = argparse.ArgumentParser()
parser.add_argument("name", choices=sorted(SERVERS))
parser.add_argument("--host", default="0.0.0.0")
parser.add_argument("--port", type=int, required=True)
args = parser.parse_args()

server = SERVERS[args.name]
if isinstance(server, MCPServer):
    server.run("streamable-http", host=args.host, port=args.port)
else:
    app = server.streamable_http_app(host=args.host)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
