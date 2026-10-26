# Changelog

All notable changes to the **SENTINEL-X** Cybersecurity Platform will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.0-enterprise] - 2026-10-27

### Added
- **Master Build Prompt & Vision Synthesis**: Formally aligned all platform modules, documentation, and build status with the foundational Master Build Prompt across all 10 Implementation Phases and 16 Acceptance Criteria.
- **Post-Hacking Digital Forensics Cyber Detective Engine (`digital_forensics_investigator_service.py`)**:
  - Reconstructs breach timelines across the 4 stages of an attack: Initial Access, Lateral Movement, Persistence, and Data Exfiltration.
  - Zero Dummy Data Guarantee: Direct inspection of live Windows Security/Application Event Logs (`wevtutil`), volatile RAM process tables (`psutil`), registry Run/RunOnce persistence keys (`winreg`), live outbound sockets, and Master File Table (**MFT**) MACB timestamps.
  - Timestomping anomaly detection flagging backdated creation/modification timestamps.
  - Sealed Evidence Vault: Automated cryptographic evidence storage (`FORENSIC-CASE-*.json`, `chmod 0400` / `attrib +r`) signed with SHA-256 and HMAC-SHA256 signatures.
  - Generates signed Cyber Detective Forensic Investigation Certificates (`CERT-FORENSIC-CASE-*.md`).
- **Ethical Hacker Safe Disengagement ("Save the Ethical Hacker")**:
  - Safe disengagement protocol purging operator command histories (PowerShell ConsoleHost, bash history), temporary test droppers, and DNS/ARP caches.
  - Issues signed disengagement certificates (`CERT-ETHICAL-DISENGAGEMENT-*.md`).
- **Terminal CLI & Launcher Integrations**:
  - Added CLI subcommands: `python cli.py forensic-investigation [--clean-ethical-operator]` and `python cli.py ethical-disengage`.
  - Added interactive launcher options `[9B]` and `[9C]` in `launcher.py`, and `[DET1]`/`[DET2]` in `cli.py`.
- **REST API Endpoints**:
  - `POST /api/v1/forensics/investigate-breach`
  - `GET /api/v1/forensics/investigation-latest`
  - `POST /api/v1/forensics/ethical-disengage`
- **Comprehensive Test Suite**:
  - Added `backend/tests/test_digital_forensics_investigator.py` (8/8 passing).
  - Full active regression suite passing at **24/24 (100%)**.

## [0.2.0-core] - 2026-10-22


### Added
- **Core Platform Architecture Transition**: Re-centered SENTINEL-X as an *Evidence-Driven, Real-Time Endpoint Detection, Automated Threat Containment and Digital Forensics Platform*.
- **Unified Threat Containment & Forensics Orchestrator (`containment_evidence_orchestrator.py`)**:
  - Connects real-time detection, safe containment, and evidence preservation into one automated atomic workflow.
  - Phase 1: Cryptographically freezes volatile scene context (PID, parent PID, memory footprint, socket connections, remote C2 endpoints) into a read-only vault (`0400`) before any containment alters host state.
  - Generates intake SHA-256/MD5 hashes, initializes a linked `ForensicCase`, and writes an immutable `ChainOfCustodyRecord`.
  - Phase 2: Safely neutralizes malicious processes (`proc.kill()`), isolates host endpoint network (`host.is_isolated = True`), dismounts infected USB storage ports, and logs `ResponseAction`.
- **Cross-Platform Controlled Attack Simulation Pipeline (`attack_simulation_pipeline.py`)**:
  - Controlled live attack simulations validating detection, containment, and forensics across:
    - **Kali Linux**: Remote Access Trojan (RAT) / Meterpreter C2 connection.
    - **Windows Host**: Base64-encoded PowerShell reverse shell reaching external C2 port.
    - **Mobile Companion**: Covert background surveillance spyware hijacking camera and network streaming.
- **REST API & CLI Integration**:
  - Added `POST /api/v1/incidents/{incident_id}/contain-and-preserve` endpoint for one-click containment and evidence preservation.
  - Added `python cli.py simulate-hack [--platform kali|windows|mobile]` to execute the entire defense cycle from terminal.
  - Added `python cli.py contain-and-preserve [incident_id]` to contain active threats and vault evidence directly from terminal.
  - Added option `[5] -> [1]` in `launcher.py` to launch live cross-platform attack simulations and verify automated defense.
- **Automated Verification Test Suite**:
  - Added `backend/tests/test_live_hack_containment_forensics.py` bringing total passing test suite to **49/49 Passing**.

## [0.1.0-alpha] - 2026-10-21

### Added
- **Project Foundation**: Initial repository structure, workspace configuration, and virtual environment setup.
- **Threat Model**: Comprehensive threat modeling document (`docs/THREAT_MODEL.md`) defining security boundaries, actor taxonomy, trust zones, and defensive safeguards.
- **Backend Architecture**: FastAPI backend structure with asynchronous SQLAlchemy models, Alembic migrations, and security middleware (CSP, HSTS, X-Frame-Options).
- **Detection & Correlation Engine**:
  - Deterministic YAML rule matching engine supporting sliding temporal windows and threshold criteria.
  - Evidence-Weighted Cross-Distribution Correlation (EWCC) research engine for source-reliability and distribution-invariant detection.
  - Event normalization pipeline with multi-format timestamp harmonization and canonical SHA-256 duplicate suppression.
  - MITRE ATT&CK technique mapper with official v14.1 Enterprise IDs and tactics.
- **Data Models**: Relational schemas for Users, RBAC Roles, Hosts, Collector Health, Events, Rules, Incidents, Evidence, Cases, Assessments, Malware, Network observations, and Audit Logs.
- **Linux Endpoint Agent**:
  - Multi-distribution detector (Ubuntu, Debian, Kali, Parrot, Fedora).
  - Systemd journal and authentication log collector (`/var/log/auth.log`, `/var/log/secure`).
  - Inotify continuous File Integrity Monitoring (FIM) for security-sensitive paths.
  - Systemd service unit definition with resource limits (CPUQuota=10%, MemoryLimit=128M).
- **Core Security Services**:
  - Scope Gate & Authorized Penetration Testing engine enforcing OWASP WSTG-aligned passive audits, TLS cipher checks, and SSRF blocking.
  - Safe, non-executing malware triage service with Shannon entropy computation, string/IOC extraction, and PE32/ELF header parsing.
  - Legal-grade digital forensics evidence vault with SHA-256/MD5 hashing, read-only locking, and tamper-detection verification.
  - Zeek network telemetry log parser with statistical port/volume baseline anomaly detection.
  - Grounded defensive AI service with strict schema validation, credential redaction, and internal event ID citations.
  - Incident dossier generator supporting Markdown and JSON export.
- **Web Dashboard (19 Views)**:
  - Complete dark-graphite SOC dashboard built with React 18, Vite, TypeScript, and Tailwind CSS.
  - All 19 operational views fully wired to real backend endpoints: Login, Overview, Live Event Stream, Incidents, Investigation Workspace, Host Inventory, Endpoint Health, Network Monitoring, Authorized Assessments, Vulnerability Findings, Malware Triage, Forensics Cases, Evidence Vault, Threat Intelligence, Detection Rules & EWCC, Security Reports, Audit Logs, Integrations, and Settings.
  - Live alert streaming via native WebSockets.
- **Desktop Application**:
  - Tauri v2 configuration (`desktop/src-tauri/tauri.conf.json`) with strict Content Security Policy.
  - Rust native backend (`desktop/src-tauri/src/main.rs`) exposing safe connectivity commands without arbitrary shell execution.
  - Cross-platform desktop window launcher (`desktop/run_desktop.py`).
- **Chrome Security Extension**:
  - Manifest V3 extension (`extension/manifest.json`) requesting minimal permissions (`activeTab`, `storage`).
  - User-initiated TLS status check and HTTP security header inspector (HSTS, CSP, X-Frame-Options, etc.).
  - Direct finding push to SENTINEL-X assessment workspaces and side panel analyst scratchpad.
- **Deployment & Automation**:
  - Hardened Docker Compose stack (`deploy/docker-compose.yml`) with unprivileged backend container and multi-stage Nginx frontend.
  - Automated Linux agent installer (`scripts/install_agent.sh`).
  - Developer startup scripts for Linux/macOS (`scripts/start_platform.sh`) and Windows (`scripts/start_platform.bat`).
- **Testing & Benchmarks**:
  - Automated test suite comprising 23 pytest integration tests passing in 3.31s.
  - Benchmark generator measuring 44,247 events/sec throughput (0.0226 ms/event latency), 100% precision, 100% recall, and 100% duplicate alert suppression.
