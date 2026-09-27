"""Run the gateway: python -m agentguard.gateway --config config/gateway.yaml --port 8000"""

import argparse
import asyncio
import logging
from pathlib import Path

import uvicorn

from agentguard.gateway.config import load_gateway_config
from agentguard.gateway.proxy import Gateway


async def main(config: Path, host: str, port: int) -> None:
    async with Gateway(load_gateway_config(config)) as gateway:
        app = gateway.app(host)
        await uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning")).serve()


parser = argparse.ArgumentParser()
parser.add_argument("--config", type=Path, default=Path("config/gateway.yaml"))
parser.add_argument("--host", default="0.0.0.0")
parser.add_argument("--port", type=int, default=8000)
args = parser.parse_args()
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
asyncio.run(main(args.config, args.host, args.port))
