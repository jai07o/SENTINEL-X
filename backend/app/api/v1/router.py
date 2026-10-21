from fastapi import APIRouter

from backend.app.api.v1.auth import router as auth_router
from backend.app.api.v1.hosts import router as hosts_router
from backend.app.api.v1.events import router as events_router
from backend.app.api.v1.incidents import router as incidents_router
from backend.app.api.v1.detection import router as detection_router
from backend.app.api.v1.assessments import router as assessments_router
from backend.app.api.v1.malware import router as malware_router
from backend.app.api.v1.forensics import router as forensics_router
from backend.app.api.v1.network import router as network_router
from backend.app.api.v1.ai import router as ai_router
from backend.app.api.v1.reports import router as reports_router
from backend.app.api.v1.audit import router as audit_router
from backend.app.api.v1.websockets import router as ws_router
from backend.app.api.v1.sockets import router as sockets_router
from backend.app.api.v1.privacy import router as privacy_router
from backend.app.api.v1.processes import router as processes_router
from backend.app.api.v1.scanner import router as scanner_router
from backend.app.api.v1.omniscan import router as omniscan_router
from backend.app.api.v1.data_management import router as data_management_router
from backend.app.api.v1.hardware_ports import router as hardware_ports_router

api_router = APIRouter()


api_router.include_router(auth_router)
api_router.include_router(hosts_router)
api_router.include_router(events_router)
api_router.include_router(incidents_router)
api_router.include_router(detection_router)
api_router.include_router(assessments_router)
api_router.include_router(malware_router)
api_router.include_router(forensics_router)
api_router.include_router(network_router)
api_router.include_router(ai_router)
api_router.include_router(reports_router)
api_router.include_router(audit_router)
api_router.include_router(ws_router)

# Advanced Endpoint, Sockets, Privacy & Workspace Security Routers
api_router.include_router(sockets_router, prefix="/sockets", tags=["Sockets & C2 Monitor"])
api_router.include_router(privacy_router, prefix="/privacy", tags=["Camera & Privacy Sentinel"])
api_router.include_router(processes_router, prefix="/processes", tags=["Background Processes"])
api_router.include_router(scanner_router, prefix="/scanner", tags=["Workspace Folder Scanner"])
api_router.include_router(omniscan_router, prefix="/omniscan", tags=["Omni Threat Scanner"])
api_router.include_router(data_management_router)
api_router.include_router(hardware_ports_router)


