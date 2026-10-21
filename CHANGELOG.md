# Changelog

All notable changes to the **SENTINEL-X** Cybersecurity Platform will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
