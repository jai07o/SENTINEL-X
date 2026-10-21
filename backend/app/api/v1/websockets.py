import json
from typing import List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import logging

logger = logging.getLogger("sentinel-ws")
router = APIRouter(tags=["Real-Time Event & Incident Stream"])


class ConnectionManager:
    """Manages active WebSocket connections for live security updates."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Active connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Broadcasts event or incident notification to all connected clients."""
        dead_connections = []
        payload = json.dumps(message, default=str)
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)


ws_manager = ConnectionManager()


@router.websocket("/ws/live")
async def websocket_live_stream(websocket: WebSocket):
    """
    Live real-time WebSocket stream for security alerts, incidents, and telemetry events.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep-alive loop; clients can also send ping/filter requests
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
