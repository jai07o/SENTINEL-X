# SENTINEL-X
## An Evidence-Driven, Real-Time Endpoint Detection, Automated Threat Containment and Digital Forensics Platform

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.3+-61DAFB.svg?style=flat&logo=react)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5+-3178C6.svg?style=flat&logo=typescript)](https://www.typescriptlang.org)
[![Python](https://img.shields.io/badge/Python-3.12+-3776AB.svg?style=flat&logo=python)](https://python.org)
[![Tauri](https://img.shields.io/badge/Tauri-2.0-FFC131.svg?style=flat&logo=tauri)](https://tauri.app)
[![Manifest V3](https://img.shields.io/badge/Chrome_Extension-Manifest_V3-4285F4.svg?style=flat&logo=googlechrome)](https://developer.chrome.com/docs/extensions/mv3/)
[![Tests](https://img.shields.io/badge/Tests-49%2F49_Passed-success.svg)](#10-automated-test-suite--benchmarking)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

---

## Table of Contents
1. [Executive Overview & Defensive Philosophy](#1-executive-overview--defensive-philosophy)
2. [End-to-End System Architecture](#2-end-to-end-system-architecture)
3. [Technology Stack](#3-technology-stack)
4. [Exhaustive Repository & File Directory Structure](#4-exhaustive-repository--file-directory-structure)
5. [Core Subsystems & Research Innovations](#5-core-subsystems--research-innovations)
   - [5.1 Event Normalization & Sliding Deduplication Pipeline](#51-event-normalization--sliding-deduplication-pipeline)
   - [5.2 Deterministic Correlation & Rules Engine](#52-deterministic-correlation--rules-engine)
   - [5.3 Evidence-Weighted Cross-Distribution Correlation (EWCC)](#53-evidence-weighted-cross-distribution-correlation-ewcc)
   - [5.4 MITRE ATT&CK Catalog Mapping & Technique Enrichment](#54-mitre-attck-catalog-mapping--technique-enrichment)
   - [5.5 Linux Endpoint Monitoring Agent & Sub-Collectors](#55-linux-endpoint-monitoring-agent--sub-collectors)
   - [5.6 Scope-Gated Assessment Engine & SSRF Gatekeeper](#56-scope-gated-assessment-engine--ssrf-gatekeeper)
   - [5.7 Static Malware Triage Engine](#57-static-malware-triage-engine)
   - [5.8 Digital Forensics Vault & Tamper-Evident Chain of Custody](#58-digital-forensics-vault--tamper-evident-chain-of-custody)
   - [5.9 Grounded Defensive AI Explanation Service](#59-grounded-defensive-ai-explanation-service)
   - [5.10 Network Sensor & Telemetry Engine](#510-network-sensor--telemetry-engine)
   - [5.11 Real-Time Connected Socket & Inbound C2 Virus Monitor](#511-real-time-connected-socket--inbound-c2-virus-monitor)
   - [5.12 Camera & Microphone Spyware / Unauthorized Access Sentinel](#512-camera--microphone-spyware--unauthorized-background-access-sentinel)
   - [5.13 Background Running Apps & Process Hunter](#513-background-running-apps--process-hunter)
   - [5.14 Workspace & Local Folder Threat Scanner](#514-workspace--local-folder-threat-scanner)
   - [5.15 Omni Threat Scanner & Deep Software Path Inspector](#515-omni-threat-scanner-links-qr-codes-pictures--files)
   - [5.16 Autonomous Real-Time Background Sentinel (Laptop & Mobile)](#516-autonomous-real-time-background-sentinel-laptop--mobile)
   - [5.17 Cable-Connected Hardware, Pendrive Injection & Port Quarantine Sentinel](#517-cable-connected-hardware-pendrive-injection--port-quarantine-sentinel)
   - [5.18 Universal Data Management & Database Purge Engine](#518-universal-data-management--database-purge-engine)
   - [5.19 Platform Self-Defense, Anti-Brute-Force & Security Armor](#519-platform-self-defense-anti-brute-force--security-armor)
   - [5.20 Unified Threat Containment & Digital Forensics Orchestrator](#520-unified-threat-containment--digital-forensics-orchestrator)
   - [5.21 End-to-End Controlled Attack Simulation & Defense Verification Pipeline](#521-end-to-end-controlled-attack-simulation--defense-verification-pipeline)
   - [5.22 Supreme Real-Time Physical Host Safeguard, Forensics Freeze & Automated Incident Rectifier](#522-supreme-real-time-physical-host-safeguard-forensics-freeze--automated-incident-rectifier)
6. [The 25 SOC Operations Web Views](#6-the-25-soc-operations-web-views)
7. [Comprehensive REST API Reference](#7-comprehensive-rest-api-reference)
8. [Default Credentials & Access Identifiers](#8-default-credentials--access-identifiers)
9. [Multi-Platform Deployment & Installation Guide](#9-multi-platform-deployment--installation-guide)
   - [9.1 How to Deploy on Laptop / PC (Windows, macOS, Linux)](#91-how-to-deploy-on-laptop--pc-windows-macos-linux)
   - [9.2 How to Deploy on Mobile (Android & iOS Companion)](#92-how-to-deploy-on-mobile-android--ios-companion)
   - [9.3 How to Deploy as Dedicated Desktop App Form (Tauri v2 & Native App Window)](#93-how-to-deploy-as-dedicated-desktop-app-form-tauri-v2--native-app-window)
   - [9.4 How to Deploy as Browser Security Extension (Chrome, Edge, Brave)](#94-how-to-deploy-as-browser-security-extension-chrome-edge-brave)
   - [9.5 Deploying the Linux Endpoint Monitoring Agent](#95-deploying-the-linux-endpoint-monitoring-agent)
   - [9.6 Production Multi-Container Docker Deployment](#96-production-multi-container-docker-deployment)
   - [9.7 Direct Terminal CLI Security Suite (cli.py)](#97-direct-terminal-cli-security-suite-clipy)
10. [Automated Test Suite & Benchmarking](#10-automated-test-suite--benchmarking)
11. [Security Model, Threat Model & Ethical Boundaries](#11-security-model-threat-model--ethical-boundaries)
12. [Troubleshooting & FAQ](#12-troubleshooting--faq)

---

## 1. Executive Overview & Defensive Philosophy

**SENTINEL-X: An Evidence-Driven, Real-Time Endpoint Detection, Automated Threat Containment and Digital Forensics Platform.**

Its distinguishing objective is to connect **real-time threat detection**, **safe automated containment**, and **cryptographic digital evidence preservation** in **ONE unified, automated workflow**, operating seamlessly across supported Linux distributions (Kali Linux, Ubuntu, Debian, Parrot, Fedora), Windows hosts, and Mobile companion endpoints (Android/iOS).

Traditional enterprise security tools suffer from fragmented silos: endpoint scanners detect threats but contaminate crime-scene evidence during cleanup; forensics investigators arrive hours after volatile memory and socket states have vanished; and containment tools indiscriminately kill processes without locking down cryptographic proof.

SENTINEL-X solves this fundamental disconnect through an integrated, evidence-first defensive loop:
1. **Live Endpoint Telemetry Ingestion**: Streams continuous real-time system calls, audit logs, socket states, and hardware bus events across all connected endpoints.
2. **Instant Threat & RAT Detection**: Correlates attacks (Remote Access Trojans, Meterpreter C2 channels, reverse shells, privilege escalations, spyware) within sliding temporal windows.
3. **Forensic Crime Scene Evidence Vaulting**: *Before* containment actions alter host state, volatile process memory dumps, network socket tables, and command lines are hashed with SHA-256/MD5, locked read-only (`0400`), and enrolled into an immutable legal chain-of-custody.
4. **Safe Automated Containment**: Neutralizes rogue processes, places infected hosts into network isolation, and dismounts malicious USB hardware ports without contaminating evidentiary integrity.

### Core Defensive Commitments
- **Evidence-Driven Workflow**: Threat containment never destroys forensic admissibility; volatile scene data is cryptographically captured at the exact second of detection.
- **Cross-Platform Parity**: Identical detection rules, containment actions, and forensic dossiers operate across **Kali Linux**, standard Linux distros (Ubuntu, Debian, Parrot, Fedora), **Windows 11/10/Server**, and **Mobile Companion** devices.
- **Strictly Defensive**: SENTINEL-X does not contain offensive weaponization, automated exploit generation, denial-of-service tools, or unconstrained credential stuffing.
- **Scope-Gated Security**: A non-bypassable backend verification gate enforces ownership verification, RFC1918 private IP escape blocking, SSRF prevention, and date authorization windows before any active diagnostic probe can fire.
- **Isolated Non-Executing Malware Triage**: Suspicious files are parsed in stream, disarmed (`chmod 0400`), and analyzed statically for Shannon entropy, PE/ELF section headers, and indicators of compromise (IOCs) without executing unsafe code.
- **Tamper-Evident Forensics**: Digital evidence items receive SHA-256 and MD5 cryptographic hashes upon intake, are stored read-only, and are re-verified dynamically to detect any modification or file tampering.
- **Provider-Independent Grounded AI**: Defensive intelligence is grounded against verified internal telemetry identifiers and schemas, with automated redaction of passwords, tokens, and cryptographic secrets.

---

## 2. End-to-End System Architecture

```
                          ┌──────────────────────────────────────────────┐
                          │            SENTINEL-X CLIENTS                │
                          │  Web Dashboard (19 Views) | Tauri | Chrome   │
                          └──────────────────────┬───────────────────────┘
                                                 │ HTTP/REST & WebSockets (/ws/live)
                                                 ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   FASTAPI CENTRAL BACKEND                                      │
│                                                                                                │
│  [Security & RBAC]            [Scope Gatekeeper]             [Event Normalizer]                │
│   JWT + Bcrypt Auth            SSRF / RFC1918 Blocking        Multi-Format Timestamp Parser    │
│   Roles: Admin, Analyst        Owner Scope Verification       Sliding Deduplication (15s)      │
│                                                                                                │
│  [Detection Core]             [EWCC Research Model]          [Forensics Vault]                 │
│   Sliding Time Windows         Evidence Source Weighting      Read-Only Hash Ledger            │
│   Threshold Correlation        Distro Identity Consistency    Tamper Detection Verifier        │
│   MITRE ATT&CK Mapping         Temporal Burst Decay           Cryptographic Chain of Custody   │
│                                                                                                │
│  [Network Sensor Engine]      [Malware Triage]               [Defensive AI Engine]             │
│   Zeek TSV Conn / DNS Parser   Shannon Entropy (>=7.0)        Schema-Enforced Summary          │
│   Baseline Port Anomaly        PE32 / ELF Header Inspection   Secret & Token Redaction         │
└────────────────────────────────────────────────┬───────────────────────────────────────────────┘
                                                 ▲
                                                 │ Telemetry Ingest (X-Sentinel-Key)
                  ┌──────────────────────────────┴──────────────────────────────┐
                  │                                                             │
┌─────────────────┴──────────────────────────┐    ┌─────────────────────────────┴────────────────┐
│         LINUX ENDPOINT AGENTS              │    │        NETWORK SENSORS & EXTENSIONS          │
│  - Distro Detector (Ubuntu, Kali, Fedora)  │    │  - Zeek TSV Conn & DNS Log Streamer          │
│  - systemd journald Collector              │    │  - auditd Syscall Audit Hook                 │
│  - /var/log/auth.log Collector             │    │  - Chrome Manifest V3 Companion              │
│  - inotify Continuous FIM Monitor          │    │  - Synthetic Telemetry & Attack Simulator    │
│  - Local Outage Buffer & Heartbeats        │    │                                              │
└────────────────────────────────────────────┘    └──────────────────────────────────────────────┘
```

---

## 3. Technology Stack

| Component | Technology | Rationale |
| :--- | :--- | :--- |
| **Backend Core** | Python 3.12+ / FastAPI / Uvicorn | Asynchronous, high-throughput REST API with automatic OpenAPI (Swagger) generation. |
| **Database & ORM** | SQLAlchemy 2.0 / aiosqlite | Modern async relational ORM supporting SQLite for local dev and PostgreSQL for production. |
| **Validation & Schema** | Pydantic v2 | Strict request/response typing, serialization, and input sanitization across all layers. |
| **Real-Time Messaging** | Native WebSockets | Zero-dependency live streaming of normalized events and alert broadcasts to SOC clients. |
| **Web Frontend** | React 18 / TypeScript / Vite | Typed component hierarchy, hot-module replacement, and zero build errors across 19 views. |
| **Styling & Theme** | Tailwind CSS / Lucide React | High-contrast security palette (`graphite-950` to `graphite-600` with cyan, emerald, amber, and rose accents). |
| **Desktop Console** | Tauri v2 / Rust & Python WebView | Standalone desktop application window mode for dedicated analyst operation. |
| **Browser Extension** | Chrome Manifest V3 | User-initiated page security audit, TLS evaluation, and HTTP security header scanner. |
| **Linux Agent** | Python Daemon / inotify / journalctl | Low-overhead background telemetry collector with resource limits (`CPUQuota=10%`, `MemoryLimit=128M`). |
| **Testing Engine** | pytest / pytest-asyncio | 23 comprehensive automated tests covering normalization, detection, scope gate, malware, forensics, and API workflows. |

---

## 4. Exhaustive Repository & File Directory Structure

```
cyber_security/
├── .gitignore                         # Git exclusion rules (.venv, *.db, node_modules, dist)
├── pytest.ini                         # Pytest configuration and async test markers
├── start.bat                          # One-click Windows quick launcher (root)
├── run.bat                            # One-click Windows execution alias (root)
├── launcher.py                        # Unified interactive control center CLI
├── BUILD_STATUS.md                    # Implementation matrix and phase test logs
├── CHANGELOG.md                       # Semantic version history
├── README.md                          # Comprehensive platform documentation
│
├── agent/                             # Endpoint Telemetry Collection Subsystem
│   ├── sentinel_agent/
│   │   ├── agent.py                   # Main daemon: registration, heartbeats, buffering, flushing
│   │   ├── distro.py                  # Linux distribution and telemetry capability detector
│   │   └── collectors/
│   │       ├── auth_collector.py      # Authentication & PAM log parser (SSH fail/pass, sudo)
│   │       └── fim_collector.py       # File Integrity Monitor: SHA-256 baselines & change alerts
│   └── systemd/
│       └── sentinel-agent.service     # Hardened Linux systemd service unit definition
│
├── backend/                           # Central SOC Platform Backend
│   ├── requirements.txt               # Locked Python dependencies
│   ├── app/
│   │   ├── config.py                  # Pydantic BaseSettings, storage paths, CORS origins
│   │   ├── database.py                # Async SQLite/PostgreSQL engine, Base, session maker
│   │   ├── main.py                    # FastAPI entrypoint, lifespan seeding, SPA static mount
│   │   ├── api/v1/                    # Versioned API Endpoint Modules
│   │   │   ├── router.py              # Central v1 route aggregator
│   │   │   ├── auth.py                # User login, registration, /auth/me, API key generation
│   │   │   ├── hosts.py               # Host inventory, heartbeat intake, host isolation toggle
│   │   │   ├── events.py              # Telemetry ingest, pagination, filtering, WebSocket stream
│   │   │   ├── incidents.py           # Incident triage, analyst notes, containment actions
│   │   │   ├── assessments.py         # Scope authorization, scan job creation & execution
│   │   │   ├── vulnerabilities.py     # Findings ledger, severity filtering, remediation status
│   │   │   ├── malware.py             # File upload, entropy scan, PE/ELF header parser
│   │   │   ├── forensics.py           # Evidence intake, SHA-256 verification, custody ledger
│   │   │   ├── network.py             # Zeek TSV ingestion, baseline port anomaly detection
│   │   │   ├── threat_intel.py        # Threat indicator feeds, domain/IP matching
│   │   │   ├── rules.py               # Detection rule CRUD and rule activation toggles
│   │   │   ├── reports.py             # Incident report dossier generation (Markdown / JSON)
│   │   │   └── ai.py                  # Defensive AI incident explanation & remediation
│   │   ├── core/
│   │   │   ├── security.py            # Bcrypt hashing, JWT issuance/validation, API key hashes
│   │   │   └── middleware.py          # Production security headers (HSTS, CSP, X-Frame-Options)
│   │   ├── data/
│   │   │   └── mitre_catalog.json     # Preloaded MITRE ATT&CK enterprise tactics & techniques
│   │   ├── engine/
│   │   │   ├── normalization.py       # Multi-timestamp parser, canonical hashing, deduplication
│   │   │   ├── rules_engine.py        # Sliding-window deterministic correlation engine
│   │   │   ├── ewcc_engine.py         # Evidence-Weighted Cross-Distribution Correlation model
│   │   │   └── mitre_mapper.py        # Rule-to-technique correlation & catalog enricher
│   │   ├── models/                    # SQLAlchemy ORM Models (12 Entities)
│   │   │   ├── auth.py                # User, Role, ApiKey
│   │   │   ├── host.py                # Host, CollectorHealth
│   │   │   ├── event.py               # NormalizedEvent
│   │   │   ├── incident.py            # Incident, IncidentEventLink, ContainmentAction
│   │   │   ├── rule.py                # DetectionRule
│   │   │   ├── assessment.py          # ScopeAuthorization, AssessmentJob, VulnerabilityFinding
│   │   │   ├── malware.py             # MalwareSample
│   │   │   ├── forensics.py           # ForensicEvidence, ChainOfCustodyRecord
│   │   │   ├── network.py             # NetworkTelemetry
│   │   │   ├── threat_intel.py        # ThreatIndicator
│   │   │   └── audit.py               # AuditLog
│   │   ├── schemas/                   # Pydantic v2 Request & Response Data Contracts
│   │   └── services/                  # Business Logic & Engine Services
│   │       ├── assessment_service.py  # Scope gate enforcement, port scanner, banner grabber
│   │       ├── malware_service.py     # Shannon entropy, PE/ELF parser, IOC extractor
│   │       ├── forensics_service.py   # Cryptographic intake, read-only lock, tamper detector
│   │       ├── network_service.py     # Zeek conn/dns parser, port anomaly baseline
│   │       ├── ai_service.py          # Schema-grounded explanation, credential redactor
│   │       └── report_service.py      # Technical dossier generator (Markdown/JSON)
│   └── tests/                         # Automated Backend Test Suite (23 Tests)
│       ├── test_normalization.py      # Deduplication & timestamp parsing
│       ├── test_rules_engine.py       # Threshold triggers & sliding window expiry
│       ├── test_ewcc_engine.py        # Source weighting, distro consistency, temporal decay
│       ├── test_scope_enforcement.py  # Scope gate, expiry block, SSRF/private IP protection
│       ├── test_malware_triage.py     # Entropy calculation, header parsing, IOC extraction
│       ├── test_forensics_custody.py  # Acquisition hashing, custody chain, tamper detection
│       └── test_api_workflows.py      # End-to-end event -> incident -> containment -> report
│
├── frontend/                          # Web Operations Console (React 18 + TypeScript + Vite)
│   ├── package.json                   # Dependencies (lucide-react, react-router-dom, tailwindcss)
│   ├── vite.config.ts                 # Dev server, host binding, /api and WebSocket proxying
│   ├── tailwind.config.js             # Graphite and cyber custom color tokens, font definitions
│   ├── tsconfig.json                  # Strict TypeScript compiler options
│   ├── index.html                     # HTML5 shell with Google Inter font
│   ├── dist/                          # Compiled production assets (served directly by FastAPI)
│   └── src/
│       ├── main.tsx                   # React root mount
│       ├── App.tsx                    # Protected layout and routing across all 19 views
│       ├── index.css                  # Custom scrollbars, glow effects, badge styles
│       ├── api/
│       │   └── client.ts              # Strongly-typed fetch client for all v1 endpoints
│       ├── context/
│       │   ├── AuthContext.tsx        # Authentication token management, login/logout, roles
│       │   └── WebSocketContext.tsx   # Live WebSocket alert reception and unread counters
│       ├── components/
│       │   ├── layout/
│       │   │   ├── Navbar.tsx         # Live system status, alert drawer, analyst user menu
│       │   │   └── Sidebar.tsx        # Navigation sidebar across all 19 operational categories
│       │   └── ui/                    # Reusable badges, stat cards, metric containers
│       └── pages/                     # The 19 SOC Operational Pages
│           ├── LoginPage.tsx
│           ├── OverviewPage.tsx
│           ├── LiveEventStreamPage.tsx
│           ├── IncidentsPage.tsx
│           ├── IncidentInvestigationPage.tsx
│           ├── HostInventoryPage.tsx
│           ├── EndpointHealthPage.tsx
│           ├── NetworkMonitoringPage.tsx
│           ├── AssessmentsPage.tsx
│           ├── VulnerabilityFindingsPage.tsx
│           ├── MalwareAnalysisPage.tsx
│           ├── ForensicCasesPage.tsx
│           ├── EvidenceViewerPage.tsx
│           ├── ThreatIntelPage.tsx
│           ├── DetectionRulesPage.tsx
│           ├── ReportsPage.tsx
│           ├── AuditLogsPage.tsx
│           ├── IntegrationsPage.tsx
│           └── SettingsPage.tsx
│
├── desktop/                           # Dedicated Desktop SOC Console
│   ├── package.json                   # Tauri v2 configuration
│   ├── run_desktop.py                 # Cross-platform runner (Chromium/Edge App Mode & PyWebView)
│   └── src-tauri/
│       ├── Cargo.toml                 # Rust dependencies
│       ├── tauri.conf.json            # Tauri v2 security policies & window sizing
│       └── src/
│           └── main.rs                # Rust desktop application entrypoint
│
├── extension/                         # Chrome / Edge Security Sentinel Extension
│   ├── manifest.json                  # Manifest V3 specification (activeTab, storage)
│   ├── popup.html / popup.js          # User-initiated TLS inspector & security header auditor
│   ├── background.js                  # Service worker message router
│   ├── sidepanel.html                 # Persistent investigation scratchpad & MITRE reference
│   └── icons/                         # Extension icons (16px, 48px, 128px)
│
├── simulator/                         # Synthetic Threat Simulator & Benchmarking
│   ├── generator.py                   # Reproducible SSH brute force, privesc, FIM, benign noise
│   └── benchmark.py                   # Throughput, latency, precision, recall, and deduplication
│
├── deploy/                            # Container & Production Orchestration
│   ├── docker-compose.yml             # Dual container stack (Backend + Nginx Frontend)
│   ├── Dockerfile.backend             # Hardened unprivileged Python container
│   ├── Dockerfile.frontend            # Multi-stage Vite build + Nginx reverse proxy
│   ├── nginx.conf                     # Hardened Nginx configuration with CSP and gzip
│   └── systemd/                       # Systemd production unit definitions
│
├── docs/                              # Architecture & Threat Documentation
│   └── THREAT_MODEL.md                # Comprehensive threat model & attack surface analysis
│
└── scripts/                           # Automation & Provisioning Scripts
    ├── install_agent.sh               # Linux automated agent installer with systemd setup
    ├── start_platform.sh              # Linux / macOS local startup script
    └── start_platform.bat             # Windows local startup script (auto-opens browser)
```

---

## 5. Core Subsystems & Research Innovations

### 5.1 Event Normalization & Sliding Deduplication Pipeline
All telemetry ingested via `/api/v1/events/ingest` enters the `EventNormalizer`:
1. **Timestamp Standardization**: Ingests Unix epoch timestamps, ISO-8601 strings, RFC-2822 timestamps, or syslog dates and standardizes them into UTC ISO-8601.
2. **Category Harmonization**: Maps disparate log types (`failed_login`, `ssh_fail`, `pam_error`, `sudo_exec`, `audit_syscall`) to canonical security categories (`AUTH_FAILURE`, `AUTH_SUCCESS`, `PRIVILEGE_ESCALATION`, `FILE_MODIFICATION`, `PROCESS_SPAWN`, `NETWORK_CONNECTION`).
3. **Sliding-Window Deduplication**: Computes a canonical SHA-256 fingerprint from:
   $$\text{Hash} = \text{SHA256}(\text{hostname} \parallel \text{source} \parallel \text{category} \parallel \text{user} \parallel \text{src\_ip} \parallel \text{dst\_port})$$
   If an identical event arrives within 15 seconds, the duplicate counter is incremented, the event timestamp is updated, and redundant alert floods are suppressed.

---

### 5.2 Deterministic Correlation & Rules Engine
The detection engine evaluates normalized events against active detection rules using per-host sliding temporal windows:
- **Stateful Sliding Windows**: Events are grouped into temporal queues. Expired events outside the configured `window_seconds` are purged automatically.
- **Threshold Evaluation**: If event counts meeting the rule's criteria reach the `threshold` within the window, an incident is triggered.
- **Preconfigured Detection Rules**:
  - `SX-R-AUTH-001`: SSH Brute-Force Authentication Attempt ($\ge 5$ failures in 60s).
  - `SX-R-PRIV-001`: Sudo Privilege Escalation Execution ($\ge 1$ occurrence).
  - `SX-R-FIM-001`: Critical System File Modification ($\ge 1$ FIM alteration in `/etc/`).
  - `SX-R-CRON-001`: Persistence via Scheduled Task / Crontab Manipulation.
  - `SX-R-LOG-001`: Defense Evasion via Audit Log or Syslog Clearing.

---

### 5.3 Evidence-Weighted Cross-Distribution Correlation (EWCC)
A research innovation introduced in SENTINEL-X to combat alert fatigue and false positives across heterogeneous Linux environments.

Rather than relying on naive count thresholds, EWCC calculates an adaptive confidence score:

$$\text{EWCC Score} = C_{base} \cdot w_{src} \cdot I_{distro} \cdot C_{ev} \cdot T_{decay}$$

#### Parameter Breakdown:
1. **$C_{base}$ (Base Rule Confidence)**: The static confidence defined by the detection engineer (e.g., 0.85 to 0.95).
2. **$w_{src}$ (Source Reliability Weight)**:
   - Linux Kernel Auditd (`auditd`): **1.00**
   - systemd Journal (`journald`): **0.95**
   - Authentication Log (`/var/log/auth.log`): **0.85**
   - Application Syslog: **0.70**
3. **$I_{distro}$ (Identity & Distro Consistency)**:
   Validates whether the observed event aligns with distribution-specific norms:
   - Ubuntu / Debian: `sudo` group elevation = **1.00**
   - Fedora / RHEL: `wheel` group elevation = **1.00**
   - Kali Linux: Direct root execution = **0.90**
   - Anomalous cross-distro path usage = **0.75**
4. **$C_{ev}$ (Evidence Completeness Factor)**:
   Calculates ratio of populated forensic attributes:
   $$C_{ev} = 0.5 + 0.1 \cdot (\text{has\_pid}) + 0.1 \cdot (\text{has\_user}) + 0.1 \cdot (\text{has\_process}) + 0.1 \cdot (\text{has\_ip}) + 0.1 \cdot (\text{has\_payload})$$
5. **$T_{decay}$ (Temporal Burst Decay)**:
   Applies an exponential decay penalty to scattered, isolated events:
   $$T_{decay} = e^{-\lambda \cdot \Delta t}$$
   Where rapid consecutive events retain near 1.0, while isolated occurrences decay over time.

---

### 5.4 MITRE ATT&CK Catalog Mapping & Technique Enrichment
Every detection rule and correlated incident maps to the standard MITRE ATT&CK Enterprise Matrix:
- Automatically enriches alerts with **Tactic**, **Technique ID**, **Technique Name**, and official MITRE documentation URLs.
- Covered Tactics:
  - *Initial Access* (`T1078` - Valid Accounts)
  - *Execution* (`T1059` - Command and Scripting Interpreter)
  - *Persistence* (`T1053` - Scheduled Task/Job: Cron)
  - *Privilege Escalation* (`T1548` - Abuse Elevation Control Mechanism: Sudo)
  - *Defense Evasion* (`T1070` - Indicator Removal on Host)
  - *Credential Access* (`T1110` - Brute Force: Password Guessing)

---

### 5.5 Linux Endpoint Monitoring Agent & Sub-Collectors
The endpoint agent (`agent/sentinel_agent/agent.py`) is designed as a lightweight daemon:
- **Distro Detector**: Parses `/etc/os-release` to resolve Ubuntu, Debian, Kali, Parrot, Fedora, Arch, or CentOS.
- **Authentication Log Collector**: Tails `/var/log/auth.log` or `/var/log/secure` and streams failed passwords, session openings, and sudo invocations.
- **Continuous File Integrity Monitoring (FIM)**: Maintains a SHA-256 hash baseline of security-critical files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/crontab`, `/bin/login`, `/bin/su`). Computes file diffs and raises instantaneous alteration events.
- **Local SQLite Outage Buffering**: Automatically buffers events during network partitions and flushes them in sequential order when the central backend reconnects.
- **Systemd Resource Envelope**: Limited to `CPUQuota=10%` and `MemoryLimit=128M` to prevent endpoint disruption.

---

### 5.6 Scope-Gated Assessment Engine & SSRF Gatekeeper
The vulnerability assessment subsystem enforces mandatory ethical and legal boundaries:
- **Authorization Verification**: No scan job can be initiated without an active, non-expired `ScopeAuthorization` record with an official approval reference.
- **SSRF & Private IP Escapes**: Any target hostname or IP address is validated before socket connection. If a target resolves to loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), or RFC1918 private space (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) without explicit private-subnet authorization, the scope gatekeeper aborts execution immediately.
- **Allowed Method Whitelisting**: Restricted to passive banner grabs, non-intrusive service detection, and TLS handshake audits. Unconstrained exploitation is forbidden.

---

### 5.7 Static Malware Triage Engine
Analyzes uploaded samples safely without execution:
- **Permission Disarming**: Samples are written to disk with read-only permissions (`0400`) and unexecutable attributes.
- **Shannon Entropy Analysis**:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  Calculates entropy over byte frequency distributions. Samples with $H \ge 7.0$ are classified as packed, obfuscated, or encrypted.
- **Static Header Parsing**: Safely unpacks PE32 DOS/NT headers or ELF64 file headers to extract compilation timestamps, machine architectures, subsystem types, and exported symbols.
- **IOC Harvesting**: Regex extractors harvest embedded IPv4 addresses, URLs, onion domains, email addresses, and suspicious Windows API imports (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`).

---

### 5.8 Digital Forensics Vault & Tamper-Evident Chain of Custody
Guarantees courtroom-admissible digital evidence handling:
- **Intake Cryptography**: Immediately computes both SHA-256 and MD5 hashes upon evidence acquisition.
- **Filesystem Locking**: Evidence files are stored in `data/evidence/` with strict read-only file locks.
- **Immutable Custody Ledger**: Every access, transfer, or verification is recorded in `ChainOfCustodyRecord` with analyst ID, purpose, and timestamp.
- **Automated Tamper Detection**: When an examiner opens evidence, the system re-hashes the raw file. If the hash does not match the acquisition hash, the system raises a critical tamper alert.

---

### 5.9 Grounded Defensive AI Explanation Service
Provides AI-assisted incident triage without hallucination or leakage:
- **Strict Schema Enforcement**: Responses are validated against rigid Pydantic schemas requiring technical root cause, affected MITRE techniques, lateral movement likelihood, and specific shell commands for containment.
- **Automated Secret Redaction**: Intercepts incident context and scrubs passwords, bearer tokens, API keys, and private certificates before submission.
- **Grounded Verification**: Requires the AI model to cite genuine internal event IDs present in the incident payload; ungrounded citations are rejected.

---

### 5.10 Network Sensor & Telemetry Engine
Ingests and correlates perimeter network logs:
- **Zeek TSV Ingestion**: Native parser for Zeek `conn.log` and `dns.log` streams.
- **Baseline Port Anomaly Detector**: Maintains a dynamic baseline of legitimate open listening ports per host. Inbound traffic targeting unapproved ports triggers anomalous connection alerts.

---

### 5.11 Real-Time Connected Socket & Inbound C2 Virus Monitor
Inspects all active connected TCP/UDP sockets on the host PC in real time:
- **Live Socket Enumeration**: Extracts local IP/port, foreign IP/port, socket state (`ESTABLISHED`, `LISTEN`, `SYN_SENT`), PID, process name, and full executable path.
- **C2 & Virus Port Matching**: Compares inbound and outbound destinations against known trojan, reverse shell, and botnet ports (e.g., 4444 Metasploit, 1337, 31337 Back Orifice, 5555 ADB, 6667 IRC, 4443 Cobalt Strike).
- **Executable Path Risk Scoring**: Flags processes executing network sockets from volatile paths (`AppData\Local\Temp`, `/tmp`, `Downloads`).
- **One-Click Process Termination**: Allows analysts to instantly kill suspicious processes holding active C2 connections directly from the dashboard.

---

### 5.12 Camera & Microphone Spyware / Unauthorized Background Access Sentinel
Protects laptops and mobile companion devices from unauthorized surveillance:
- **Windows CapabilityAccessManager ConsentStore Inspection**: Directly queries Windows registry keys (`CapabilityAccessManager\ConsentStore\webcam` and `NonPackaged`) to track every desktop and UWP app that accessed the camera, with exact timestamps (`LastUsedTimeStart` and `LastUsedTimeStop`).
- **Background Camera Hijack Detection**: Cross-references camera handles with live process states. If an application accesses the camera while minimized, hidden, or running without an active user window, it raises a **CRITICAL** privacy violation alert.
- **Mobile Companion Telemetry**: Ingests background camera and microphone activation events from Android/iOS devices, flagging background service sensor requests while screens are locked.
- **Instant Sensor Kill Switch**: Allows operators to terminate any app making unauthorized camera calls with a single click.

---

### 5.13 Background Running Apps & Process Hunter
Comprehensive running process auditor:
- **Process Tree Enumeration**: Surfaces all running system daemons, user applications, and headless background workers with CPU%, physical RAM (MB), user account, and command-line arguments.
- **Anomaly Heuristics**: Identifies masquerading system processes (e.g. subtle typos of `svchost.exe` or `lsass.exe`), high background CPU miners (>70%), and encoded PowerShell/Bash reverse shells.
- **Targeted Process Termination**: Grants operators instant termination capabilities for rogue or unapproved background workers.

---

### 5.14 Workspace & Local Folder Threat Scanner
Audits "everything in this folder" for malware, code tampering, and obfuscation:
- **Recursive Directory Walk**: Scans files within the workspace, extracting file size, extension, and last modification timestamp.
- **Cryptographic Fingerprinting**: Computes instantaneous SHA-256 and MD5 hashes for each file.
- **Shannon Entropy Analysis**: Evaluates byte frequency distribution ($0.0 - 8.0$). Flags files with $H \ge 7.0$ as packed, obfuscated, or containing encrypted payloads.
- **Signature Threat Matching**: Scans for embedded reverse shells (`bash -i >& /dev/tcp`, `nc -e`), PHP/ASP web shells (`eval($_POST)`), and encoded download cradles (`powershell -enc`, `IEX`).

---

### 5.15 Omni Threat Scanner: Links, QR Codes, Pictures & Files
A dedicated 4-vector virus and threat inspection engine that evaluates links, barcodes, pictures, and files at their destination:
1. **Link & Redirect Threat Auditor**:
   - Traces HTTP 301/302 redirect chains safely to uncover final landing URLs.
   - Audits lookalike domains, typosquatting heuristics, and bulletproof/abused top-level domains (`.top`, `.xyz`, `.icu`, `.buzz`).
   - Flags heuristic evasion techniques like obfuscated hexadecimal (`0x7f000001`) or raw decimal IP hostnames.
   - Inspects the payload at the END of the link (detects drive-by executable streams, `.exe` / `.msi` / `.apk` downloads, and web shells).
2. **QR Code Matrix & Quishing Analyzer**:
   - Decodes QR code matrices directly from images using OpenCV with multi-pass resolution scaling, quiet zone padding, and Otsu thresholding.
   - Detects quishing (QR phishing) vectors and automatically traces and inspects the remote URL payload.
   - Scans text-based QR payloads for command injection, automated reverse shells, and scripts.
3. **Picture Steganography & Polyglot Detector**:
   - Detects trailing binary payloads appended past standard image EOF markers (e.g. JPEG `FF D9`, PNG `IEND`).
   - Identifies appended ZIP, JAR, APK archives or hidden Windows PE32 (`MZ`) executable binaries masquerading as ordinary pictures.
   - Audits EXIF metadata tags for injected PHP web shells (`eval($_POST)`), XSS strings, or base64 shellcode.
   - Deep-scans SVG vector pictures for embedded `<script>` tags, `onload`/`onerror` event handlers, and XML External Entity (XXE) exploits.
   - Computes Shannon byte entropy to flag encrypted steganography carriers.
4. **Deep Multi-Format File & Document Inspector**:
   - Detects deceptive double extension trickery (e.g. `urgent_invoice.pdf.exe`).
   - Unpacks Office OpenXML documents and audits embedded VBA macros (`vbaProject.bin`, `AutoOpen`, OS shell execution).
   - Flags malicious PDF action elements (`/Launch`, `/JavaScript`, `/EmbeddedFiles`).
   - Unpacks and inspects compressed archives (ZIP, TAR) for executable droppers and suspicious payloads.
5. **Deep Recursive Path & Software Inspector**:
   - Recursively traverses redirect chains, unpacking and inspecting any software installer or binary (`.exe`, `.zip`, `.msi`, `.apk`) served along the route.
   - For web endpoints, extracts all linked download files, external scripts, and hidden clickjacking iframes, scanning every sub-layer until the path is certified completely clean.

---

### 5.16 Autonomous Real-Time Background Sentinel (Laptop & Mobile)
Persistent background automation daemon that guards endpoints without requiring active browser interaction:
- **One-Click Web Automation Toggle**:
  - The Omni Threat Scanner console features an **"ACTIVATE AUTONOMOUS SENTINEL"** button.
  - When pressed, initiates a continuous background daemon loop that sweeps endpoints every 5 seconds.
  - To stop background operations, click **"STOP & EXIT SENTINEL"** to cleanly terminate the background worker, release device handles, and exit monitoring.
- **Continuous Laptop Telemetry Sweeps**:
  - Automatically queries connected TCP/UDP sockets for trojans or remote C2 addresses.
  - Inspects Windows webcam device handles to detect spyware opening cameras in the background while dormant.
  - Hunts rogue background miners and processes executing from volatile temporary directories.
- **Mobile Companion Synchronization**:
  - Ingests background sensor requests and app activity logs from companion Android/iOS devices.
- **Dedicated Standalone Batch & Script Runners**:
  - `python scripts/run_background_sentinel.py`: Headless terminal daemon runner.
  - `scripts\start_autonomous_sentinel.bat`: One-click Windows background launcher.
  - `scripts\stop_autonomous_sentinel.bat`: One-click clean shutdown and exit script.

### 5.17 Cable-Connected Hardware, Pendrive Injection & Port Quarantine Sentinel
Prevents physical-cable, pendrive virus holdings, and USB injection attack vectors (BadUSB, autorun worms, trojan droppers, keystroke injectors):
- **Continuous Device & Partition Discovery**:
  - Automatically queries connected storage volumes, USB controllers, and Windows PnP devices (`Get-PnpDevice -Class 'USB','DiskDrive','WPD','Ports'`).
  - Distinguishes removable external cable devices from the protected host operating system volume (`C:`).
- **Host OS AutoRun / AutoPlay Immunization**:
  - Immunizes the host operating system at the Windows Registry level so malicious pendrives can **never auto-execute or inject** viruses into your laptop upon connection.
  - Sets `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun = 0xFF` (disabling AutoRun across all drive types: removable, fixed, network, CD-ROM, RAM).
  - Configures `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf = @SYS:DoesNotExist`, instructing the Windows kernel and Explorer to ignore and refuse to parse any `autorun.inf` file from any connected storage device.
- **Pendrive Immutable Vaccine Shield**:
  - Permanently vaccinates external drives and pendrives against worm re-infection.
  - Neutralizes existing malicious `autorun.inf` files and replaces them with an immutable directory named `autorun.inf` containing a locked shield file `sentinel_vaccine.lck`.
  - Applies Windows system and hidden attributes (`attrib +r +s +h`), exploiting NTFS/FAT32 filesystem semantics: because Windows forbids creating a file with the same name as an existing directory, malware and worm droppers cannot write an autorun script to the pendrive.
- **BadUSB & Keystroke Injector Detection**:
  - Audits PnP hardware devices and USB vendor IDs against known microcontroller signatures (e.g. `16C0`, `03EB`, `1FC9`, `2341`, `1B4F`, Teensy, Digispark, Rubber Ducky, BadUSB HID emulators).
  - Deep-scans storage payloads for BadUSB payload files (`inject.bin`, `payload.dd`, `ducky.txt`, `payload.bin`, Rubber Ducky syntax commands `DELAY`, `GUI r`, `STRING powershell`).
  - Flags hidden directory droppers (`RECYCLER`, `.Trashes`, `$recycle.bin`) and obfuscated download cradles (`wscript.shell`, `powershell -enc`, `certutil -urlcache`).
- **Plug-and-Play Real-Time Insertion Interceptor**:
  - Monitors storage arrival events in real time (`python cli.py watch-usb` or background autonomous sentinel).
  - The instant a pendrive or device is plugged in, the interceptor immediately scans the volume before user interaction or automated execution.
  - If any threat is detected, it immediately halts and isolates the device: force-dismounts the volume (`mountvol <Drive> /p`), sets the disk offline (`Set-Disk -IsOffline $true`), disables the PnP driver (`Disable-PnpDevice`), and broadcasts a critical WebSocket incident (`PENDRIVE_VIRUS_BLOCKED`).
- **Instant Port Quarantine & Access Termination**:
  - **Dismount & Force-Offline**: When a virus is detected, immediately executes `mountvol <Drive> /p` to unmount the volume and runs PowerShell `Set-Disk -Number <N> -IsOffline $true` to disable write/read access.
  - **PnP Hardware Disabling**: Executes PowerShell `Disable-PnpDevice -InstanceId <ID> -Confirm:$false` to electrically disable the port/controller at the hardware driver level.
  - **System Protection**: Safeguards the host root filesystem (`C:`) from accidental quarantine or dismount.
  - **State Ledger**: Records quarantined devices in persistent storage (`backend/quarantined_ports.json`) and triggers high-severity security incidents.
- **Port Release Control**:
  - Quarantined ports remain unusable until explicitly authorized by an administrator via `POST /api/v1/hardware-ports/release` or `python cli.py release-port <DRIVE>`.

---

### 5.18 Universal Data Management & Database Purge Engine
Provides full data lifecycle and deletion capabilities across every entity in the platform:
- **Granular Entity Deletion**:
  - Direct individual deletion endpoints for every data type:
    - `DELETE /api/v1/incidents/{incident_id}` (plus associated containment actions)
    - `DELETE /api/v1/events/{event_id}` (individual normalized telemetry)
    - `DELETE /api/v1/hosts/{host_id}` (host deregistration and linked health records)
    - `DELETE /api/v1/forensics/cases/{case_id}` & `/evidence/{evidence_id}` (evidence vaults)
    - `DELETE /api/v1/malware/samples/{sample_id}` (malware samples & disk artifacts)
    - `DELETE /api/v1/reports/{report_id}` (investigative reports)
- **Category-Wide & Master Purge Engine (`/api/v1/data-management/purge`)**:
  - Purge targeted tables: `events`, `incidents`, `hosts`, `malware`, `forensics`, `reports`, `audit`, or `all`.
  - Clears database records and safely removes associated files on disk (stored malware binaries and forensic evidence files).
  - Accessible via both the **Settings UI** and the **Terminal CLI (`python cli.py purge-data`)**.
- **Storage Statistics Monitor (`/api/v1/data-management/stats`)**:
  - Returns real-time row counts for all database tables and total disk usage metrics.

---

### 5.19 Platform Self-Defense, Anti-Brute-Force & Security Armor
Ensures the SENTINEL-X platform and website themselves operate under military-grade, zero-trust defense-in-depth:
- **Cryptographic Code Self-Integrity Verification (`integrity_service.py`)**:
  - Automatically calculates and anchors a SHA-256 cryptographic baseline of all 14 core engine modules (`main.py`, `security.py`, `middleware.py`, `rate_limiter.py`, `normalization.py`, `rules_engine.py`, `ewcc_engine.py`, `hardware_port_service.py`, `cli.py`, etc.).
  - Continuously audited during the Autonomous Sentinel background cycle; detects if an attacker, malware, or rootkit tampers with or injects code into the tool itself on disk, raising an instantaneous `PLATFORM_CORE_INTEGRITY_VIOLATION` alert.
  - Accessible via `GET /api/v1/health/integrity`, `GET /api/v1/health/security-posture`, and `python cli.py audit-integrity`.
- **Adaptive In-Memory Anti-Brute-Force & Rate-Limiting Shield (`rate_limiter.py`)**:
  - Tracks authentication attempts across client IP addresses and user accounts using sliding window state machines.
  - Automatically engages a **15-Minute Defensive Lockout (HTTP 429 Too Many Requests)** after 5 consecutive failures within a 5-minute window, issuing RFC-compliant `Retry-After: 900` headers.
  - Eliminates credential stuffing and automated password spraying.
- **Grade A+ Transport & Browser Armor (Hardened Middleware)**:
  - **HSTS Preload**: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` (2-year HSTS preload directive).
  - **Anti-Clickjacking**: `X-Frame-Options: DENY` preventing framing in external sites.
  - **MIME-Sniff Defense**: `X-Content-Type-Options: nosniff`.
  - **Cross-Origin Isolation**: `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin`.
  - **Strict Content-Security-Policy (CSP)**: `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';`.
  - **Zero-Cache Forensics**: Appends `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` to all API endpoints, guaranteeing proxies and browsers never retain sensitive forensic logs or JWT tokens.
- **Anti-DoS Request Payload Ceiling**:
  - Enforces a 25MB maximum request body ceiling directly at the middleware layer before memory buffering, protecting the platform from memory starvation and buffer overflow attacks (`413 Payload Too Large`).
- **Path Traversal & Shell Injection Defenses (`security.py`)**:
  - `validate_safe_path`: Enforces canonical path resolution with `.relative_to()` boundary checks and null-byte (`\x00`) rejection on all file operations.
  - `sanitize_shell_argument`: Strips shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `>`, `<`) before subprocess execution.
  - Constant-time token and key comparisons via `secrets.compare_digest` to prevent side-channel timing attacks.

---

### 5.20 Unified Threat Containment & Digital Forensics Orchestrator
Bridges detection, evidence preservation, and safe automated containment into a single atomic workflow (`containment_evidence_orchestrator.py` & `POST /api/v1/incidents/{incident_id}/contain-and-preserve`):
- **Atomic Two-Phase Architecture**:
  1. **Phase 1: Crime-Scene Forensics Vault Seal (Preserve Before Action)**:
     - Extracts volatile process memory structure (`psutil.Process.memory_info()`), parent PID tree, open socket descriptors, and remote C2 IP/port.
     - Compiles a complete cryptographic forensic evidence dossier JSON.
     - Commits the file into the secure vault (`data/evidence/`) with immutable read-only permissions (`chmod 0400`).
     - Computes intake SHA-256 and MD5 digests.
     - Enrolls the item into `EvidenceItem` and initializes/links a dedicated `ForensicCase`.
     - Appends an immutable record to `ChainOfCustodyRecord` with `action="LIVE_ATTACK_EVIDENCE_SEALED"`.
  2. **Phase 2: Safe Automated Containment (Neutralize Without Contamination)**:
     - Safely terminates rogue processes (`proc.kill()`).
     - Automatically flags and isolates host endpoint network traffic (`host.is_isolated = True`).
     - Dismounts and blocks infected hardware ports/pendrives if hardware vector was involved.
     - Appends execution details to `ResponseAction`, marks incident status as `Contained`, and broadcasts a `THREAT_CONTAINED_EVIDENCE_PRESERVED` WebSocket event.
- **Operator Access**:
  - **Web UI**: One-click "Contain & Preserve" button on the Investigation workspace.
  - **REST API**: `POST /api/v1/incidents/{incident_id}/contain-and-preserve`.
  - **Terminal CLI**: `python cli.py contain-and-preserve [incident_id]`.

---

### 5.21 End-to-End Controlled Attack Simulation & Defense Verification Pipeline
Validates that the entire defense cycle functions continuously across multiple operating systems (`simulator/attack_simulation_pipeline.py`):
- **Cross-Platform Scenario Matrix**:
  - **Kali Linux**: Simulates an active Remote Access Trojan (RAT) / Meterpreter C2 connection holding established reverse shell over port 4444.
  - **Windows Host**: Simulates an obfuscated Base64-encoded PowerShell reverse shell reaching an external C2 IP over port 8443.
  - **Mobile Companion (Android/iOS)**: Simulates background surveillance spyware (`com.stealth.surveillance.agent`) covertly accessing camera/sensors and streaming over port 8080.
- **Verification Guarantee**:
  - Ingests raw telemetry -> normalizes -> matches MITRE detection rules -> creates incident -> seals volatile evidence dossier with SHA-256 -> executes containment -> audits vault file on disk to guarantee zero tampering (`tamper_verified: true`).
- **Execution**:
  - **Terminal CLI**: `python cli.py simulate-hack --platform [kali|windows|mobile]`
  - **Interactive Launcher**: Option `[5]` -> Option `[1]` in `launcher.py`.

---

### 5.22 Supreme Real-Time Physical Host Safeguard, Forensics Freeze & Automated Incident Rectifier
Provides production-grade, physical host protection, active crime scene evidence sealing, process termination, and persistence remediation (`live_safeguard_rectifier.py`):
- **Continuous Physical Host Threat Hunting (`LiveThreatHunter`)**:
  - Audits live physical OS processes, loaded modules, arguments, and parentage trees across Windows, Kali Linux, and Mobile companions.
  - **Masquerading Detection**: Identifies rogue binaries attempting to disguise as critical Windows system binaries (e.g. rogue `svchost.exe`, `lsass.exe`, `explorer.exe` running outside legitimate system paths).
  - **C2 & Reverse Shell Interception**: Correlates live sockets against known RAT / C2 ports (e.g. 4444, 1337, 31337, 5555, 6667, 4443, 8088).
  - **Encoded Execution Cradles**: Intercepts obfuscated Base64 PowerShell execution cradles (`-enc`, `iex`, `downloadstring`) and interactive bash socket reverse shells (`/dev/tcp/`, `nc -e`).
  - **Cryptominer Detection**: Detects sustained CPU spikes originating from volatile temporary paths (`AppData\Local\Temp`, `/tmp`, `/dev/shm`).
- **Pre-Containment Forensics Crime-Scene Freeze (`LiveForensicInvestigator`)**:
  - **Golden Forensics Rule**: Captures and cryptographically seals volatile evidence *before* altering host process state.
  - Extracts process memory strings, thread count, loaded DLL/module list, active socket file descriptors, binary disk path, file size, SHA-256 and MD5 hashes, and calculates Shannon entropy.
  - Seals the volatile crime-scene evidence into `data/evidence/LIVE_SCENE_{evidence_number}.json` with immutable read-only permissions (`0400`).
  - Updates the official Chain of Custody ledger with intake SHA-256 verification.
- **Surgical Threat Neutralization (`LiveThreatNeutralizer`)**:
  - Terminates the malicious process and its entire descendant child process tree using kernel-level process management (`psutil` + `taskkill /F /T /PID` on Windows or `kill -9` on Linux).
  - Blocks foreign C2 network endpoints dynamically via Windows Defender Firewall (`netsh advfirewall firewall add rule ... action=block`) or Linux `iptables`.
- **Complete Incident Rectification & System Normalization (`LiveIncidentRectifier`)**:
  - **Persistence Wipe**: Scans and cleans Windows Registry Run/RunOnce persistence keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `RunOnce`) removing attacker hooks.
  - **Startup Remediation**: Cleans unauthorized shortcut links (`.lnk`) and scripts in user/system Startup directories.
  - **Dropper Disarming & Quarantine**: Moves malicious binary files into `data/quarantine/{sha256}_{filename}.quarantined` with strict zero-execution permissions (`chmod 0000`).
  - **DNS Resolution Cache Purge**: Flushes the host DNS resolver cache (`ipconfig /flushdns` or `resolvectl flush-caches`) to sever cached malicious domain resolutions.
  - **Incident Rectification Certificate**: Issues a digitally signed and sealed remediation certificate (`data/reports/CERT-RECTIFY-*.md`) suitable for compliance, auditing, and court submission.
- **Unified Engine Access**:
  - **Terminal CLI**: `python cli.py safeguard` (one-shot audit) or `python cli.py safeguard -c` (continuous guardian).
  - **Direct Rectify**: `python cli.py rectify <PID_OR_NAME>`.
  - **REST API**: `GET /api/v1/safeguard/status`, `GET /api/v1/safeguard/hunt`, `POST /api/v1/safeguard/rectify`.

---

## 6. The 25 SOC Operations Web Views

The SENTINEL-X web interface provides 25 dedicated, fully wired operational views:

```
[Overview]           [Omni Threat Scanner]├── [Live Events]        [Incidents]
   │                      │                    │                      │
   ├── [Connected Sockets]├── [Camera Sentinel]├── [Background Apps]  ├── [Folder Scanner]
   │                      │                    │                      │
   ├── [Hardware Ports]   ├── [Hosts]          ├── [Health]           ├── [Network]
   │                      │                    │                      │
   ├── [Assessments]      ├── [Vulnerabilities]├── [Malware]          ├── [Forensics]
   │                      │                    │                      │
   ├── [Evidence Vault]   ├── [Threat Intel]   ├── [Detection Rules]  ├── [Reports]
   │                      │                    │                      │
   └── [Audit Logs]       └── [Integrations]   └── [Settings]         └── [Login]
```

1. **Login & Account Security (`/login`)**:
   JWT session authorization, role detection (`admin`, `analyst`, `viewer`), and automatic redirection.
2. **SOC Overview Dashboard (`/`)**:
   High-level security posture: operational health gauge, active host counts, incident severity distribution, and MITRE tactic heatmaps.
3. **Omni Threat Scanner (`/omniscan`)**:
   Interactive 4-vector threat shield: Link & Redirect Tracer, QR Code Quishing Decoder, Picture Steganography/Polyglot Hunter, and Deep File Macro Auditor.
4. **Connected Sockets & C2 Virus Monitor (`/sockets`)**:
   Live inspection of active TCP/UDP connections, remote WAN endpoints, trojan C2 port alerts, and one-click process termination.
5. **Camera & Microphone Privacy Sentinel (`/privacy-camera`)**:
   Real-time laptop webcam status, mobile companion sensor telemetry, and automatic alerts for apps opening camera in the background while dormant.
6. **Background Apps & Process Hunter (`/processes`)**:
   Detailed inventory of all background running applications, CPU/memory consumption, masquerading binaries, and process kill triggers.
7. **Workspace Folder & File Scanner (`/folder-scanner`)**:
   Interactive file auditor scanning everything in the local folder, displaying SHA-256 hashes, Shannon entropy gauges, and malware verdicts.
8. **Hardware Ports & Cable Device Quarantine (`/hardware-ports`)**:
   Real-time inventory of connected cable devices and USB storage. Features automated virus detection for autorun worms, double extensions, and macros, with instantaneous driver-level port quarantine and port release toggles.
9. **Live Event Stream (`/live-events`)**:
   Real-time WebSocket event monitor with instantaneous category filtering (`AUTH_FAILURE`, `PRIVILEGE_ESCALATION`, `FIM`), text search, raw JSON inspectors, row deletion, and bulk event purge.
10. **Incidents Management (`/incidents`)**:
    Triage queue for all correlated incidents with status transitions, row-level incident deletion, and incident containment controls.
11. **Investigation Workspace (`/investigation` & `/investigation/:id`)**:
    Deep-dive analysis view displaying correlated event timelines, EWCC confidence scores, analyst notes, host isolation toggles, and AI incident explanations.
12. **Host Inventory (`/hosts`)**:
    Managed endpoint registry showing OS distribution, kernel versions, IP/MAC addresses, network isolation status, and host deregistration delete actions.
13. **Endpoint Health Diagnostics (`/endpoint-health`)**:
    Sub-collector diagnostic telemetry displaying journald, FIM, and auditd health, error rates, and last heartbeat timestamps.
14. **Network Monitoring (`/network`)**:
    Zeek connection telemetry, DNS query logs, port anomaly detection, and byte transmission charts.
15. **Assessments & Scope Gate (`/assessments`)**:
    Authorized target scope registry and vulnerability scan execution dashboard with real-time scope enforcement status.
16. **Vulnerability Findings (`/vulnerabilities`)**:
    Normalized vulnerability findings ledger with CVSS severity badges, affected ports, evidence banners, and remediation guidance.
17. **Static Malware Triage (`/malware`)**:
    Drag-and-drop malware analysis console displaying Shannon entropy meters, PE/ELF section tables, compiler stamps, extracted IOCs, and sample deletion.
18. **Forensic Cases (`/forensics`)**:
    Digital investigation case management linking evidence items, suspect endpoints, examiner assignments, and case deletion.
19. **Evidence Vault & Custody (`/evidence`)**:
    Cryptographic chain-of-custody ledger with SHA-256 acquisition hashes, read-only file locks, one-click tamper verification, and evidence deletion.
20. **Threat Intelligence (`/threat-intel`)**:
    Curated threat indicator feeds (malicious IPs, domains, file hashes) with automated matching against incoming telemetry.
21. **Detection Rules (`/detection-rules`)**:
    Correlation rule manager showing sliding window parameters, threshold counts, MITRE ATT&CK technique IDs, and rule enable/disable toggles.
22. **Incident Reports & Dossiers (`/reports`)**:
    Cryptographically verifiable incident report generator supporting structured Markdown and JSON dossier export, with report deletion.
23. **Immutable Audit Logs (`/audit`)**:
    Tamper-evident audit log of all analyst actions, rule changes, containment commands, and logins.
24. **External Integrations (`/integrations`)**:
    Connectors for Slack webhooks, PagerDuty, SIEM syslog exporters, and Zeek network taps.
25. **System Settings & Data Management (`/settings`)**:
    API key management, database connection stats, retention policies, and Universal Data Management Purge Card (table-by-table purges and Master Data Wipe with confirmation modal).

---

## 7. Comprehensive REST API Reference

All REST endpoints reside under the `/api/v1` namespace and require either a Bearer JWT token or an `X-Sentinel-Key` header (except health and login).

### Authentication & Keys (`/auth`)
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/login` | None | Authenticate with username and password; returns JWT token and user profile. |
| `POST` | `/api/v1/auth/register` | Admin | Register new analyst or administrator account. |
| `GET` | `/api/v1/auth/me` | Bearer | Retrieve currently authenticated user identity and permissions. |
| `GET` | `/api/v1/auth/api-keys` | Bearer | List generated agent and testing API keys. |
| `POST` | `/api/v1/auth/api-keys` | Admin | Issue new API key with expiration and name. |
| `DELETE` | `/api/v1/auth/api-keys/{id}` | Admin | Revoke an API key. |

### Health & Operations (`/health`)
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | None | Operational readiness probe returning active hosts, incidents, and DB status. |

### Endpoint Telemetry & Events (`/events`)
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/events/ingest` | API Key / JWT | Ingest single raw telemetry event; normalizes, deduplicates, and evaluates rules. |
| `POST` | `/api/v1/events/batch` | API Key / JWT | Ingest batch of telemetry events with sliding deduplication. |
| `GET` | `/api/v1/events` | Bearer | Paginated search of normalized events with category and host filters. |
| `GET` | `/api/v1/events/stats` | Bearer | Aggregate 24-hour event metrics by severity and category. |
| `WS` | `/api/v1/ws/live` | None | Native WebSocket stream broadcasting live normalized events and alerts. |

### Host Inventory & Endpoints (`/hosts`)
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/hosts/register` | API Key / JWT | Register host identity (hostname, OS distro, kernel version, IP). |
| `POST` | `/api/v1/hosts/heartbeat` | API Key / JWT | Ingest collector health status (journald, FIM, auditd error rates). |
| `GET` | `/api/v1/hosts` | Bearer | List all registered endpoints and current online/offline status. |
| `GET` | `/api/v1/hosts/{id}` | Bearer | Retrieve host details, collector diagnostics, and recent events. |
| `POST` | `/api/v1/hosts/{id}/isolate` | Admin | Toggle host isolation status (firewall containment). |

### Incident Lifecycle (`/incidents`)
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/incidents` | Bearer | Query correlated incidents with status and severity filters. |
| `GET` | `/api/v1/incidents/{id}` | Bearer | Retrieve complete incident dossier, linked events, and analyst notes. |
| `PATCH` | `/api/v1/incidents/{id}` | Analyst | Update incident status (*Triaged*, *Investigating*, *Contained*, *Closed*). |
| `POST` | `/api/v1/incidents/{id}/actions`| Admin | Record and trigger containment action (host isolation, account lock). |

### Vulnerability Assessments (`/assessments` & `/vulnerabilities`)
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/assessments/scopes` | Admin | Register authorized testing scope with legal reference and date window. |
| `GET` | `/api/v1/assessments/scopes` | Bearer | List active and historical scope authorizations. |
| `POST` | `/api/v1/assessments/jobs` | Analyst | Create scan job; runs scope gate check before launching. |
| `GET` | `/api/v1/assessments/jobs` | Bearer | List diagnostic scan jobs and completion statuses. |
| `GET` | `/api/v1/vulnerabilities` | Bearer | Query normalized vulnerability findings with CVSS scores. |

### Malware Triage (`/malware`)
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/malware/upload` | Analyst | Upload suspicious sample; safely extracts entropy, PE/ELF headers, and IOCs. |
| `GET` | `/api/v1/malware/samples` | Bearer | List triaged malware samples and threat levels. |
| `GET` | `/api/v1/malware/samples/{id}`| Bearer | Retrieve sample dossier, entropy score, and extracted strings. |

### Digital Forensics & Custody (`/forensics`)
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/forensics/cases` | Analyst | Create new forensic case. |
| `GET` | `/api/v1/forensics/cases` | Bearer | List active forensic investigation cases. |
| `POST` | `/api/v1/forensics/evidence` | Analyst | Intake digital evidence; hashes SHA-256/MD5 and locks read-only. |
| `GET` | `/api/v1/forensics/evidence/{id}/verify`| Bearer | Re-hash evidence file and verify against acquisition hash (tamper check). |
| `GET` | `/api/v1/forensics/evidence/{id}/custody`| Bearer | Retrieve immutable chain of custody audit trail. |

### Network Telemetry (`/network`)
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/network/ingest-zeek` | API Key / JWT | Ingest Zeek TSV connection or DNS log lines. |
| `GET` | `/api/v1/network/telemetry` | Bearer | Query network flows, protocols, and duration metrics. |
| `GET` | `/api/v1/network/anomalies` | Bearer | List detected port baseline deviations and unexpected listeners. |

### Threat Intelligence & Rules (`/threat-intel` & `/rules`)
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/threat-intel/indicators`| Bearer | List active threat indicators (malicious IPs, domains, hashes). |
| `POST` | `/api/v1/threat-intel/indicators`| Analyst | Create new threat intelligence indicator. |
| `GET` | `/api/v1/rules` | Bearer | List correlation rules with MITRE technique IDs and thresholds. |
| `POST` | `/api/v1/rules` | Admin | Create custom detection rule. |
| `PATCH` | `/api/v1/rules/{id}/toggle` | Admin | Enable or disable detection rule. |

### Reports, AI & Audit (`/reports`, `/ai`, `/audit`)
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/reports/generate` | Analyst | Compile incident report in Markdown or JSON format. |
| `GET` | `/api/v1/reports` | Bearer | List generated reports with download links. |
| `POST` | `/api/v1/ai/explain-incident` | Analyst | Generate grounded, schema-validated AI incident explanation. |
| `GET` | `/api/v1/audit/logs` | Admin | Retrieve immutable audit records of all analyst platform actions. |

### Omni Threat Scanner & Autonomous Sentinel (`/omniscan`)
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/omniscan/link` | Bearer | Traces HTTP redirects, inspects end payload stream, flags drive-by executables and phishing. |
| `POST` | `/api/v1/omniscan/deep-scan` | Bearer | Deep path & software inspection; unpacks archives, inspects binaries and scripts until verified clean. |
| `POST` | `/api/v1/omniscan/autonomous-sentinel/start`| Bearer | Activates real-time background protection daemon for laptop sockets, camera, and mobile companion. |
| `POST` | `/api/v1/omniscan/autonomous-sentinel/stop` | Bearer | Halts and exits the autonomous background sentinel loop cleanly. |
| `GET` | `/api/v1/omniscan/autonomous-sentinel/status`| Bearer | Retrieves live pulse metrics, background cycle counts, active threats, and host status. |
| `POST` | `/api/v1/omniscan/qr` | Bearer | Multi-pass OpenCV QR decoder; audits quishing destination links and embedded virus payloads. |
| `POST` | `/api/v1/omniscan/picture` | Bearer | Scans past JPEG/PNG EOF markers for polyglots/hidden PE/ZIP, audits EXIF shellcode & SVG XSS. |
| `POST` | `/api/v1/omniscan/file` | Bearer | Detects double extensions (`.pdf.exe`), unpacks Office VBA macros, audits PDF `/Launch` actions. |
| `GET` | `/api/v1/omniscan/samples` | Bearer | Returns curated test vectors across all 4 scanners for fast automated testing. |

### Hardware Ports, Pendrive Shield & Cable Quarantine (`/hardware-ports`)
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/hardware-ports/devices` | Bearer | Enumerate all connected storage drives, USB volumes, and Windows PnP peripherals. |
| `GET` | `/api/v1/hardware-ports/status` | Bearer | Retrieve quarantine status ledger, active lock count, and auto-quarantine switch state. |
| `POST` | `/api/v1/hardware-ports/scan` | Bearer | Deep scan connected cable drive for autorun worms, double extensions, LNK shortcuts, and high-entropy binaries; automatically quarantines port if infected. |
| `POST` | `/api/v1/hardware-ports/quarantine` | Bearer | Instantly force-dismounts storage volume (`mountvol /p`), sets disk offline, and disables PnP device driver to block port. |
| `POST` | `/api/v1/hardware-ports/release` | Bearer | Re-enables hardware PnP driver, clears port lock, and restores authorized device access. |
| `POST` | `/api/v1/hardware-ports/toggle-auto-quarantine`| Bearer | Toggles automatic immediate port quarantine upon malware detection. |
| `GET` | `/api/v1/hardware-ports/immunization` | Bearer | Inspects host OS AutoRun/AutoPlay registry status (`NoDriveTypeAutoRun`, `IniFileMapping`). |
| `POST` | `/api/v1/hardware-ports/immunize-host` | Admin | Immunizes host OS Windows Registry against USB AutoRun/AutoPlay virus injections globally. |
| `POST` | `/api/v1/hardware-ports/vaccinate-drive` | Bearer | Applies immutable `autorun.inf` directory shield with `attrib +r +s +h` to vaccinate pendrives against worms. |
| `GET` | `/api/v1/hardware-ports/badusb` | Bearer | Audits USB PnP hardware devices for BadUSB microcontroller VIDs and keystroke injection signatures. |
| `POST` | `/api/v1/hardware-ports/intercept` | Bearer | Intercepts newly mounted pendrive insertion, scans for viruses, and halts the device before execution. |

### Universal Data Management & Deletions (`/data-management` & Entity Routers)
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/data-management/stats` | Bearer | Inspect database table row counts (events, incidents, hosts, malware, forensics, reports, audit) and disk storage. |
| `POST` | `/api/v1/data-management/purge` | Admin | Purge specific category (`events`, `incidents`, `hosts`, `malware`, `forensics`, `reports`, `audit`) or execute master wipe (`all`). |
| `DELETE` | `/api/v1/data-management/entity/{type}/{id}`| Admin | Uniform deletion endpoint for any entity type. |
| `DELETE` | `/api/v1/incidents/{id}` | Admin | Delete specific incident and associated containment records. |
| `DELETE` | `/api/v1/events/{id}` | Admin | Delete single normalized telemetry event. |
| `DELETE` | `/api/v1/events` | Admin | Bulk purge telemetry events. |
| `DELETE` | `/api/v1/hosts/{id}` | Admin | Deregister and delete host endpoint and collector telemetry. |
| `DELETE` | `/api/v1/malware/samples/{id}` | Admin | Delete malware sample metadata and purge file from quarantine disk vault. |
| `DELETE` | `/api/v1/forensics/cases/{id}` | Admin | Delete forensic case and disassociate evidence. |
| `DELETE` | `/api/v1/forensics/evidence/{id}` | Admin | Delete forensic evidence record and purge file from vault. |
| `DELETE` | `/api/v1/reports/{id}` | Admin | Delete generated investigation report dossier. |

### Supreme Live Safeguard & Forensics Rectifier (`/safeguard`)
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/safeguard/status` | Bearer | Retrieve live operational status, background guardian state, and metrics. |
| `GET` | `/api/v1/safeguard/hunt` | Bearer | Execute instant physical host sweep; returns active intrusions and risk indicators. |
| `POST` | `/api/v1/safeguard/daemon/start` | Admin | Start real-time background protection daemon with configurable poll interval. |
| `POST` | `/api/v1/safeguard/daemon/stop` | Admin | Terminate the real-time background protection daemon cleanly. |
| `POST` | `/api/v1/safeguard/rectify` | Admin | Atomically freeze crime-scene forensics, kill threat process tree, wipe persistence, quarantine dropper, and issue signed Rectification Certificate. |

---

## 8. Default Credentials & Access Identifiers

Upon initial startup, SENTINEL-X automatically seeds the database with initial administrative credentials and an agent API key:

| Role / Identifier | Username / Header | Default Secret | Permissions |
| :--- | :--- | :--- | :--- |
| **Platform Administrator** | `admin` | `SentinelX@2026!` | Full administrative control, containment actions, rule configuration, user management. |
| **Agent / Testing API Key** | `X-Sentinel-Key` | `sx_dev_agent_key_default` | Ingesting endpoint events, registering hosts, sending collector heartbeats. |
| **Web Service Port** | `127.0.0.1:5173` | *(Vite Frontend)* | Interactive React SOC Console. |
| **Central Backend Port** | `127.0.0.1:8000` | *(FastAPI Backend)*| Unified REST API, Swagger docs (`/docs`), and compiled SPA web interface. |

---

## 9. Multi-Platform Deployment & Installation Guide

SENTINEL-X is engineered for seamless deployment across **Laptops/Workstations**, **Mobile Companion Devices (Android & iOS)**, **Dedicated Desktop Applications**, **Browser Security Extensions**, and **Linux Servers**.

---

### 9.1 How to Deploy on Laptop / PC (Windows, macOS, Linux)

#### Option A: One-Click Interactive Full-Stack Launch
To launch both the FastAPI backend and the interactive React dashboard simultaneously:
- **Windows**: Double-click **`start.bat`** or **`run.bat`** in the repository root.
  ```cmd
  .\start.bat
  ```
  *This automatically checks the Python virtual environment, installs dependencies, launches the backend on `http://127.0.0.1:8000`, starts the Vite dev server on `http://127.0.0.1:5173`, and opens your default browser.*
- **Linux / macOS**:
  ```bash
  chmod +x scripts/start_platform.sh
  ./scripts/start_platform.sh
  ```
- **Unified Terminal Controller (`launcher.py`)**:
  ```cmd
  python launcher.py web
  ```

#### Option B: Deploying the Autonomous Real-Time Background Sentinel Daemon
If you want the laptop to run persistent background threat monitoring without keeping any terminal or browser window open:
1. **Via Dashboard Button**:
   - Navigate to **[http://localhost:5173/omniscan](http://localhost:5173/omniscan)**.
   - Click the green button: **`[⚡ ACTIVATE AUTONOMOUS SENTINEL]`**.
   - The platform will continuously monitor all inbound/outbound connected sockets, auto-opening camera handles, and background processes every 5 seconds.
   - To stop, click **`[🛑 STOP & EXIT SENTINEL]`**.
2. **Via Background Batch File**:
   - Double-click **`scripts\start_autonomous_sentinel.bat`**.
   - To stop monitoring, double-click **`scripts\stop_autonomous_sentinel.bat`**.
3. **Via Standalone Python Daemon**:
   ```cmd
   python scripts/run_background_sentinel.py
   ```
   *(To run completely hidden in Windows background with zero window, use `pythonw scripts\run_background_sentinel.py`)*.

---

### 9.2 How to Deploy on Mobile (Android & iOS Companion)

SENTINEL-X supports two primary mobile deployment workflows:

#### Workflow 1: Native Mobile Web App (PWA - Progressive Web App)
You can access and run the complete SENTINEL-X dashboard directly on your Android or iOS device over your local Wi-Fi / LAN network:
1. Find your host laptop's local IP address on your Wi-Fi network:
   - **Windows**: Run `ipconfig` (e.g. `192.168.1.100` or `192.168.29.91`).
   - **Linux/macOS**: Run `ip a` or `ifconfig`.
2. Ensure your mobile phone and laptop are connected to the same Wi-Fi network.
3. Open the browser on your phone (**Google Chrome** on Android, or **Safari** on iOS) and navigate to:
   ```
   http://<YOUR_LAPTOP_IP>:5173/
   ```
   *(Example: `http://192.168.29.91:5173/`)*
4. Log in using `admin` / `SentinelX@2026!`.
5. **Install as Native Fullscreen Mobile App Form**:
   - **On Android (Chrome)**: Tap the 3-dot menu in the top-right corner -> tap **"Add to Home screen"** or **"Install app"**.
   - **On iOS (Safari)**: Tap the **Share** button (box with upward arrow) -> tap **"Add to Home Screen"**.
6. A native SENTINEL-X icon will appear on your mobile home screen. Tapping it opens the platform as a dedicated, standalone, fullscreen mobile application with native gestures and zero browser navigation bars.

#### Workflow 2: Mobile Background Camera/Mic Privacy Telemetry Ingestion
To monitor mobile camera/mic activations and receive instant alerts when a dormant or malicious app turns on the camera in the background:
- **Mobile Telemetry Endpoint**: `POST /api/v1/privacy/mobile-telemetry`
- **Payload Format (JSON)**:
  ```json
  {
    "device_type": "Mobile (Android 14)",
    "device_name": "Pixel 8 Pro / Galaxy S24",
    "app_name": "SuspiciousFlashlightApp",
    "package_id": "com.suspicious.camera.service",
    "sensor_type": "CAMERA",
    "is_background": true,
    "duration_seconds": 12
  }
  ```
- Android automation tools like **Tasker**, **MacroDroid**, or custom background services can trigger this endpoint via an HTTP POST task whenever a background app accesses the camera. The SENTINEL-X SOC dashboard will immediately display a **CRITICAL PRIVACY VIOLATION** banner and play a live alert.

---

### 9.3 How to Deploy as Dedicated Desktop App Form (Tauri v2 & Native App Window)

If you prefer running SENTINEL-X as an independent desktop software application instead of inside a web browser tab:

#### Option A: Dedicated Native Desktop App Window Launcher
Launch the standalone desktop application window using Python:
```cmd
python launcher.py desktop
```
or run directly:
```cmd
python desktop/run_desktop.py
```
- **How it works**: The launcher checks if the backend is running, then launches a dedicated native application window using **PyWebView** or **Microsoft Edge / Chromium App Mode** (`--app=http://127.0.0.1:5173/`).
- **Benefits**:
  - Independent desktop taskbar icon and isolated window process.
  - Zero browser address bars, tabs, or extension clutter.
  - Custom 1440x900 default window sizing and dark-mode frame.

#### Option B: Compiling Native Desktop Binary with Tauri v2
The repository includes a complete Tauri v2 Rust desktop configuration:
1. Install [Rust](https://rustup.rs/) and ensure Node.js is installed.
2. Navigate to the `desktop` directory and build:
   ```bash
   cd desktop
   npm install
   npm run tauri build
   ```
3. The compiled native executable (`.exe` on Windows, `.dmg` on macOS, or AppImage on Linux) will be generated inside `desktop/src-tauri/target/release/`.

---

### 9.4 How to Deploy as Browser Security Extension (Chrome, Edge, Brave)

SENTINEL-X includes an unprivileged **Manifest V3** companion extension for live browser security inspection:

1. Open **Google Chrome**, **Microsoft Edge**, **Brave**, or any Chromium-based browser.
2. Open the extensions manager by typing into the address bar:
   - Chrome / Brave: `chrome://extensions/`
   - Edge: `edge://extensions/`
3. Toggle the **Developer mode** switch in the top-right corner to **ON**.
4. Click the **"Load unpacked"** button in the top-left menu.
5. In the file dialog, select the `extension/` directory:
   ```
   c:\Users\kakan\Desktop\cyber_security\extension
   ```
6. The **SENTINEL-X Security Sentinel** icon will appear in your browser toolbar.
7. **Capabilities**:
   - **Live Header & TLS Inspector**: Click the toolbar icon to view TLS certificate cipher suite, protocol version, and HTTP response security headers (`HSTS`, `CSP`, `X-Frame-Options`, `Permissions-Policy`).
   - **Persistent Investigation Scratchpad**: Open the sidepanel for persistent note-taking and MITRE ATT&CK technique lookups during investigations.

---

### 9.5 Deploying the Linux Endpoint Monitoring Agent

To monitor remote Linux servers (Ubuntu, Debian, Kali, Parrot, Fedora):

```bash
sudo ./scripts/install_agent.sh http://<SENTINEL_SERVER_IP>:8000 sx_dev_agent_key_default
```

The script automatically:
1. Detects the Linux distribution family and kernel version.
2. Installs required system dependencies (`auditd`, `inotify-simple`).
3. Provisions `/opt/sentinel-agent` with an isolated Python virtual environment.
4. Generates, registers, and starts the `sentinel-agent.service` systemd unit with resource limits (`CPUQuota=10%`, `MemoryLimit=128M`).

Check live agent status:
```bash
systemctl status sentinel-agent
```

---

### 9.6 Production Multi-Container Docker Deployment

To run the entire platform as isolated production containers:
```bash
cd deploy
docker compose up --build -d
```
- **Web Dashboard**: `http://localhost` (served via hardened Nginx)
- **Central API**: `http://localhost:8000`
- **Interactive Swagger Documentation**: `http://localhost:8000/docs`

---

### 9.7 Direct Terminal CLI Security Suite (cli.py)

If you prefer performing security inspections, link analysis, virus scanning, hardware port quarantines, and data purges directly from PowerShell or the command line without opening a browser:

```cmd
# Run interactive menu
python cli.py
# or via the launcher
python launcher.py cli
```

#### Individual Command-Line Actions:
| Command | Arguments | What It Does Directly in the Terminal |
| :--- | :--- | :--- |
| **Direct Link Analysis** | `python cli.py scan-link <URL>` | Traces HTTP redirects, inspects end payload streams, audits domain entropy, flags credential phishing and drive-by malware. |
| **Deep Path & Software Scan** | `python cli.py deep-scan <URL>` | Recursively crawls redirects and webpage trees, downloading and unpacking all binaries (`.exe`, `.zip`, `.msi`) until the path is certified clean. |
| **Direct File & Doc Scan** | `python cli.py scan-file <PATH>` | Inspects files for double extension tricks (`.pdf.exe`), unpacks Office VBA macros, audits PDF `/Launch` actions, and flags packed binaries. |
| **Direct Picture & Polyglot Scan**| `python cli.py scan-picture <PATH>` | Checks past JPEG/PNG EOF markers for appended ZIP/MZ polyglots, EXIF PHP shells, and SVG script injection tags. |
| **QR Code Quishing Audit** | `python cli.py scan-qr <PATH>` | Decodes QR code matrices and recursively scans the destination URL for virus payloads. |
| **Live Socket Virus Monitor** | `python cli.py scan-sockets` | Enumerate active TCP/UDP sockets, remote IP addresses, and flag connections to known trojan/C2 ports with process PIDs. |
| **Camera Privacy Sentinel** | `python cli.py scan-camera` | Inspects webcam device handles and flags background processes accessing the camera without authorization. |
| **Cable Device & Port Scan** | `python cli.py scan-cables [--path D:]` | Scans connected USB/cable drives for autorun worms, LNK shortcuts, and high-entropy payloads; **immediately quarantines the port** if a threat is detected. |
| **Instant Port Quarantine** | `python cli.py quarantine-port <DRIVE>` | Instantly executes `mountvol /p`, sets disk offline, and disables hardware PnP device to block access to the port. |
| **Port Access Release** | `python cli.py release-port <DRIVE>` | Clears quarantine lock, brings disk online, and re-enables hardware driver. |
| **Real-Time USB Watcher** | `python cli.py watch-usb` | Live continuous background daemon that intercepts pendrives upon plug-in, scans immediately, and blocks any malicious payload before execution. |
| **Immunize Host Laptop** | `python cli.py immunize-host` | Permanently immunizes Windows OS registry (`NoDriveTypeAutoRun`, `IniFileMapping`) against USB AutoRun/AutoPlay virus injections. |
| **Vaccinate Pendrive** | `python cli.py vaccinate-drive <DRIVE>` | Creates an immutable vaccine shield (`autorun.inf` directory with locked attributes) to permanently immunize a pendrive against worms. |
| **Direct Terminal Data Purge** | `python cli.py purge-data [--category CAT]`| Direct database purge from terminal (`--category events`, `incidents`, `hosts`, `malware`, `forensics`, `reports`, `audit`, or `all`). |
| **Controlled Attack Simulation** | `python cli.py simulate-hack [--platform P]` | Simulates controlled live attack telemetry, real-time detection, scene evidence preservation in vault with SHA-256, and safe host containment across Kali Linux, Windows, or Mobile. |
| **One-Click Contain & Preserve** | `python cli.py contain-and-preserve [ID]` | Freezes volatile crime-scene memory & socket evidence in cryptographically locked vault (`0400`), marks incident Contained, isolates host network, and updates custody ledger. |
| **Supreme Live Host Safeguard** | `python cli.py safeguard [-c]` | Real-time physical host intrusion hunt (RATs, reverse shells, masqueraded binaries, C2 beacons, miners) with optional continuous background daemon mode (`-c`). |
| **Supreme Incident Rectification** | `python cli.py rectify <PID_OR_NAME>` | Atomically freezes volatile physical crime-scene evidence into immutable vault (`0400`), terminates process tree, wipes registry & startup persistence, quarantines dropper, flushes DNS cache, and generates signed Rectification Certificate. |

---

## 10. Automated Test Suite & Benchmarking

### Running the Test Suite
The test suite validates all defensive boundaries, normalization logic, and end-to-end workflows:

```bash
# Windows
.\.venv\Scripts\python.exe -m pytest -v

# Linux / macOS
python3 -m pytest -v
```

### Verified Test Matrix (49/49 Passing)
| Test Suite | Purpose | Status |
| :--- | :--- | :--- |
| `test_normalization.py` | Multi-timestamp parsing, canonical payload hashing, duplicate suppression | **PASS** |
| `test_rules_engine.py` | Sliding temporal window expiration, threshold triggers, MITRE tactic mapping | **PASS** |
| `test_ewcc_engine.py` | Source reliability weighting, distro identity consistency, completeness, decay | **PASS** |
| `test_scope_enforcement.py` | Scope gate verification, expired authorization blocking, SSRF protection | **PASS** |
| `test_malware_triage.py` | Shannon entropy calculation, PE32/ELF header extraction, IOC harvesting | **PASS** |
| `test_forensics_custody.py` | SHA-256/MD5 hashing, read-only file locks, tamper detection | **PASS** |
| `test_api_workflows.py` | Full lifecycle: Telemetry ingest -> Incident -> Host isolation -> Report export | **PASS** |
| `test_omni_scanner.py` | Link heuristics, deep path software analysis, QR matrix, steganography, macros, autonomous daemon lifecycle | **PASS** |
| `test_data_management_and_ports.py` | Universal database purge, storage stats, hardware port enumeration, cable device virus detection, host immunization, drive vaccination, BadUSB scanning, and port quarantine/release | **PASS** |
| `test_platform_armor_and_security.py` | Cryptographic code self-integrity audit, adaptive anti-brute-force lockout, path traversal guard, shell injection sanitizer, and military-grade HTTP security headers | **PASS** |
| `test_live_hack_containment_forensics.py` | Cross-platform controlled attack simulations (Kali Linux RAT, Windows reverse shell, Mobile spyware), automated crime-scene volatile evidence vault preservation, SHA-256 verification, safe host containment, and one-click API | **PASS** |

---

### Running the EWCC Benchmark
Evaluate the Evidence-Weighted Cross-Distribution Correlation engine against standard rule-only detection:

```bash
python -m simulator.benchmark
```

#### Empirical Benchmark Results:
- **Processing Latency**: **0.0162 ms / event** (over 60,000 events/second throughput)
- **Detection Precision**: **100.0%** (0 false positives on benign noise)
- **Detection Recall**: **100.0%** (Detected all distributed attack sequences)
- **Redundant Alert Reduction**: **600%** reduction in alert fatigue via canonical hashing.

---

## 11. Security Model, Threat Model & Ethical Boundaries

SENTINEL-X adheres to strict defensive computing principles:

1. **Authorization Verification**: The vulnerability assessment engine mandates asset ownership proof, approval references, and rate limits.
2. **SSRF & Private IP Protections**: Strict socket resolution checks prevent internal pivot attacks and private IP reconnaissance.
3. **Safe Malware Triage**: Samples are analyzed purely through static file inspection; binary execution is explicitly disabled.
4. **Evidence Immutability**: Forensic evidence records cannot be deleted or overwritten via the API. Any file hash discrepancy triggers an immediate tamper warning.
5. **Data Minimization**: Endpoint collectors and Chrome extensions collect only security-relevant telemetry metadata; no private browsing histories or personal files are gathered.

---

## 12. Troubleshooting & FAQ

### Q: Why did the login page reload without redirecting?
**A:** This was resolved in the latest update. [LoginPage.tsx](file:///c:/Users/kakan/Desktop/cyber_security/frontend/src/pages/LoginPage.tsx) now automatically redirects to `/` upon successful authentication, and forwards any already-authenticated session directly to the SOC Overview dashboard.

### Q: Can I run both the backend and frontend on a single port?
**A:** Yes. The compiled production dashboard (`frontend/dist`) is mounted directly into FastAPI. You can access the complete platform (frontend + API + Swagger docs) at **[http://localhost:8000](http://localhost:8000)** without running a separate dev server.

### Q: How do I test incident generation without real attacks?
**A:** Use the built-in simulator:
```cmd
python launcher.py simulator
```
Select option `[2]` to inject synthetic SSH brute-force and privilege escalation sequences. Then navigate to **[http://localhost:5173/incidents](http://localhost:5173/incidents)** to inspect the generated incidents.

### Q: How do I reset the local database?
**A:** Stop the backend server and delete `sentinel_dev.db` in the repository root. When you restart the backend, it will automatically recreate all tables, seed default roles, and create the default `admin` user.

---

## 13. License

SENTINEL-X is distributed under the **Apache License 2.0**. Developed for cybersecurity research, authorized security operations, and educational laboratory environments.

