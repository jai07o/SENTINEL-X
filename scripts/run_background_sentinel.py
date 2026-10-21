#!/usr/bin/env python3
"""
SENTINEL-X: Autonomous Background Host & Mobile Sentinel Daemon.
Can be executed as a background process or service:
python scripts/run_background_sentinel.py --daemon
"""
import sys
import time
import signal
import logging
import asyncio
from pathlib import Path

# Ensure root directory is on PYTHONPATH
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.app.services.autonomous_sentinel_service import autonomous_sentinel_service

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("sentinel-daemon")

running = True


def handle_exit(signum, frame):
    global running
    logger.info(f"Received shutdown signal ({signum}). Exiting background sentinel...")
    running = False


async def main():
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    logger.info("=================================================================")
    logger.info("   SENTINEL-X AUTONOMOUS BACKGROUND SENTINEL ENGAGED (DAEMON)    ")
    logger.info("=================================================================")
    logger.info("Monitoring connected sockets, camera handles, processes, and companion mobile telemetry...")

    res = await autonomous_sentinel_service.start()
    logger.info(f"Sentinel Service: {res.get('message')}")

    try:
        while running and autonomous_sentinel_service.is_active:
            await asyncio.sleep(2)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Stopping background sentinel...")
    finally:
        await autonomous_sentinel_service.stop()
        logger.info("Autonomous Sentinel cleanly terminated.")


if __name__ == "__main__":
    asyncio.run(main())
