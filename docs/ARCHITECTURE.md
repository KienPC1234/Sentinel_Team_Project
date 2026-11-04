# ShieldCall VN — Architecture

**ShieldCall VN** is an enterprise-grade digital safety and cyber-fraud mitigation platform designed to detect, analyze, and neutralize multifaceted threats across telecommunication, financial, digital communication, and executable file vectors.

The platform employs a hybrid asynchronous architecture combining real-time ASGI WebSocket/SSE streams, background distributed task workers, GPU-accelerated neural computing, and an isolated Zero-Trust Docker Sandbox backed by industry-standard forensic toolsets.

---

## 1. System Architecture Topology

```mermaid
flowchart TD
 subgraph ClientTier["Client & Integration Layer"]
 WebUI["Web Frontend & PWA"]
 MobileClient["Mobile Client / Native Application"]
 MCPClient["Claude Desktop & MCP Agents"]
 APIClient["External REST API Consumers"]
 end

 subgraph IngressTier["Perimeter & Ingress Security"]
 ReverseProxy["Reverse Proxy / Cloudflare WAF / TLS (:443)"]
 end

 subgraph AppTier["Application & Routing Tier (PM2 Cluster)"]
 DaphneServer["Daphne ASGI Server (:8001)<br/>Django 5.2 | Channels 4 | DRF"]
 PuppeteerCluster["Puppeteer Headless Cluster (:3010)<br/>Anti-SSRF DNS Resolver | Stealth Engine"]
 end

 subgraph DataTier["Storage, State & Cache Broker"]
 RedisNode["Redis 8.x<br/>Cache | Channel Layer | Celery Broker"]
 DatabaseNode[("MariaDB 11.x / MySQL 8.x<br/>Relational Storage & Auth")]
 end

 subgraph WorkerTier["Distributed Task Engine (Celery)"]
 CeleryWorker["Celery Worker Cluster<br/>Multi-threaded Thread Pool"]
 CeleryBeat["Celery Beat Scheduler<br/>Periodic Threat Sync"]
 end

 subgraph NeuralTier["Hardware-Accelerated Neural Computing"]
 VietOCRNode["VietOCR Engine<br/>NVIDIA CUDA GPU / CPU (shared AI service)"]
 WhisperNode["Faster-Whisper STT<br/>NVIDIA CUDA GPU"]
 FAISSNode["FAISS Vector DB<br/>Nomic Embed 768-dim"]
 end

 subgraph SandboxTier["Zero-Trust Execution Sandbox (Docker)"]
 DockerSandbox["sentinel-sandbox:latest<br/>--network none | --read-only | --cap-drop ALL"]
 YARAEngine["YARA Multi-Vector Signature Rules"]
 OLEToolsEngine["OLETools VBA Macro Dissector"]
 PEFileEngine["PEFile Entropy & Imphash Inspector"]
 PyPDFEngine["PyPDF Stream & Exploit Decoder"]
 ClamAVEngine["ClamAV Antivirus Daemon"]
 end

 subgraph InferenceTier["Large Language Model Inference"]
 OllamaDaemon["Ollama Daemon (:11434)"]
 PrimaryLLM["Primary: deepseek-v4.1-flash:cloud"]
 ClassifierLLM["Classifier: gemma4"]
 end

 WebUI --> ReverseProxy
 MobileClient --> ReverseProxy
 MCPClient --> ReverseProxy
 APIClient --> ReverseProxy

 ReverseProxy --> DaphneServer
 DaphneServer --> PuppeteerCluster
 DaphneServer --> RedisNode
 DaphneServer --> DatabaseNode

 RedisNode <--> CeleryWorker
 CeleryBeat --> RedisNode
 CeleryWorker --> DatabaseNode

 CeleryWorker --> VietOCRNode
 CeleryWorker --> WhisperNode
 CeleryWorker --> FAISSNode

 CeleryWorker --> DockerSandbox
 DockerSandbox --> YARAEngine
 DockerSandbox --> OLEToolsEngine
 DockerSandbox --> PEFileEngine
 DockerSandbox --> PyPDFEngine
 DockerSandbox --> ClamAVEngine

 DaphneServer --> OllamaDaemon
 CeleryWorker --> OllamaDaemon
 OllamaDaemon --> PrimaryLLM
 OllamaDaemon --> ClassifierLLM
```

---

## 2. Multi-Vector Threat Analysis Pipeline

The platform evaluates artifacts across six dedicated investigation vectors, aggregates findings into structured telemetry, and executes heuristic and neural risk classification:

```mermaid
flowchart LR
 subgraph Ingestion["Input Ingestion Layer"]
 InPhone["Telephony / MSISDN"]
 InBank["Financial Account"]
 InWeb["Domain / URL"]
 InMedia["Visual Media (Images)"]
 InAudio["Acoustic Audio (.wav/.mp3)"]
 InFile["Executable / Document File"]
 end

 subgraph Engines["Vector Processing Modules"]
 ModPhone["Phone Pipeline<br/>E.164 Normalize + Blacklist"]
 ModBank["Financial Pipeline<br/>VietQR Resolution + Fraud DB"]
 ModWeb["Web Intelligence<br/>DNS/MX + WHOIS + Puppeteer"]
 ModMedia["Vision Pipeline<br/>VietOCR + QR Matrix"]
 ModAudio["Acoustic Pipeline<br/>Faster-Whisper CUDA + Voice Intel"]
 ModFile["Zero-Trust Sandbox<br/>Docker + YARA + PEFile + ClamAV"]
 end

 subgraph Synthesis["Intelligence Aggregation & LLM Reasoning"]
 Aggregator["Threat Intelligence Aggregator"]
 RAGIndex["FAISS Vector Search<br/>Local Knowledge Base"]
 LLMEval["Ollama Reasoning Engine<br/>DeepSeek-v4.1-Flash / Gemma4"]
 end

 subgraph Verdict["Standardized Verdict"]
 Score["Risk Score (0 - 100)"]
 Badge["Threat Level (SAFE / WARNING / CRITICAL)"]
 Guidance["Actionable Remediation Guidance"]
 end

 InPhone --> ModPhone
 InBank --> ModBank
 InWeb --> ModWeb
 InMedia --> ModMedia
 InAudio --> ModAudio
 InFile --> ModFile

 ModPhone --> Aggregator
 ModBank --> Aggregator
 ModWeb --> Aggregator
 ModMedia --> Aggregator
 ModAudio --> Aggregator
 ModFile --> Aggregator

 Aggregator --> RAGIndex
 RAGIndex --> LLMEval
 Aggregator --> LLMEval

 LLMEval --> Score
 LLMEval --> Badge
 LLMEval --> Guidance
```

### 2.1 Vector Analysis Capabilities

- **Telecommunication & Number Scoring**: Normalizes international and domestic Vietnamese MSISDN formats, cross-referencing threat telemetry, carrier assignments, and community scam reports.
- **Financial Account Verification**: Performs programmatic lookup and beneficiary name resolution via VietQR integration, cross-referencing fraud intelligence databases.
- **Domain & Web Intelligence**: Inspects DNS MX records, domain age (WHOIS), SSL reputation, and ScamAdviser / Trustpilot metrics via SSRF-isolated relays.
- **Email & Messaging Forensics**: Dissects `.eml` and text messages, validating SPF, DKIM, and DMARC DNS alignment to identify spoofed corporate or government origins.
- **Multi-Modal AI Analysis**:
  - **Audio Streams**: Acoustic transcription via `Faster-Whisper` running on NVIDIA CUDA followed by psychological manipulation and urgency indicator extraction.
  - **Visual Media**: Image OCR via `VietOCR` (Vietnamese Transformer served by the shared `pkv-ai` process; `ocr_bridge.py` is the fallback) combined with QR code matrix decoding and phishing banner classification.
- **Malware & APK Sandbox**: Dissects Windows binaries and Android APK packages in isolated Docker environments using YARA rules, PEFile, and ClamAV.
- **Social Engineering & Crypto Forensics**: Tracks Telegram channels, Zalo groups, fake VNeID portals, and suspicious crypto wallet addresses.

### 2.2 Zero-Trust Local Malware Sandbox Engine

Replaces third-party external dependencies with an entirely isolated on-premise containment engine:

- **Containment Model**: Every suspicious file is mounted read-only inside an ephemeral container (`sentinel-sandbox:latest`) with strict enforcement:
  - `--network none`: Complete network isolation. Zero external telemetry or outbound egress.
  - `--read-only`: Read-only root filesystem prevents modification or persistent writes.
  - `--tmpfs /tmp:rw,size=256m,mode=1777`: Bounded writable scratch space (needed for archive unpacking / AV temp files) that never persists.
  - `--cap-drop ALL`: Drops all Linux kernel capabilities.
  - `--security-opt=no-new-privileges:true`: Prevents privilege escalation.
  - `--memory 1g --cpus 2.0 --pids-limit 64`: Throttles resource abuse and prevents fork bombs.

> The long-running daemon (`sentinel-sandbox-daemon`, port 5005) runs with `--read-only`, `--security-opt=no-new-privileges:true`, and tmpfs mounts (`mode=1777`) for `/tmp` + `/var/run/clamav` (the latter lets the ClamAV daemon bind its socket); because it must accept inbound HTTP it keeps the default bridge network (no egress is performed by the analyzer).

- **Multi-Engine Static & Heuristic Dissection**:
  - **YARA Engine**: Scans binary patterns for ransomware extortion notes, process injection calls, and obfuscated droppers.
  - **OLETools (`olevba`)**: Dissects VBA macro streams in `.doc`, `.docx`, `.xls`, `.xlsx`, `.xlsm` files to detect `Auto_Open`, `Shell()`, and `WScript.Shell`.
  - **PEFile Engine**: Computes `imphash`, analyzes section Shannon entropy, and flags critical injection APIs (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`).
  - **PyPDF Dissection**: Flags `/Launch` system execution commands, `/EmbeddedFiles` droppers, and `/JS` JavaScript streams.
  - **ClamAV Engine**: Cross-references against updated open-source antivirus definitions.

### 2.3 Hardened Puppeteer Headless Web Cluster

- **Anti-SSRF Isolation**: Validates all target hostnames and DNS resolutions to block access to private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.169.254`).
- **Anti-Detection Stealth**: Employs `puppeteer-extra-plugin-stealth` with automated flag masking (`navigator.webdriver` removal, custom humanized User-Agents).
- **Leak Prevention & Resource Optimization**: Utilizes `WeakMap` page tracking, blocks heavy media streams (`audio`, `video`, `fonts`), and automatically recycles browser instances after 50 renders to release accumulated V8 memory.

### 2.4 Model Context Protocol (MCP) Remote Server

Exposes Sentinel threat tools directly to external AI agents, Claude Desktop, and IDE plugins over the standardized Model Context Protocol:

```mermaid
flowchart TD
 subgraph Clients["User & Agent Clients"]
 WebChat["Web AI Assistant (/ai-assistant/)"]
 ClaudeDesk["Claude Desktop / MCP Client Host"]
 end

 subgraph MCPGateway["Protocol Router & SSE Gateway"]
 SSEStream["SSE Event Stream (:8001/api/v1/mcp/sse/)"]
 JSONRPC["JSON-RPC Message Relay (:8001/api/v1/mcp/messages/)"]
 end

 subgraph Tools["Exposed Forensic MCP Tools"]
 ToolPhone["check_phone"]
 ToolURL["check_url_or_domain"]
 ToolBank["check_bank_account"]
 ToolMsg["analyze_message"]
 ToolEmail["check_email_sender"]
 ToolThreat["lookup_scam_db"]
 ToolTrends["get_scam_radar_trends"]
 ToolFull["scan_full_incident"]
 end

 subgraph Engine["Ollama / DeepSeek LLM"]
 Reasoning["Reasoning & Synthesis (DeepSeek-v4.1-Flash)"]
 end

 WebChat --> SSEStream
 ClaudeDesk --> SSEStream
 SSEStream --> JSONRPC
 JSONRPC --> Tools
 Tools --> Reasoning
 Reasoning --> SSEStream
```

- **Discovery Endpoint**: `GET /api/v1/mcp/`
- **SSE Transport Stream**: `GET /api/v1/mcp/sse/`
- **JSON-RPC Message Relay**: `POST /api/v1/mcp/messages/`
- **Exposed Tools (10)**: `check_phone`, `check_bank_account`, `check_url_or_domain`, `analyze_message`, `check_email_sender`, `get_supported_banks`, `lookup_scam_db`, `get_scam_radar_trends`, `scan_full_incident`, `report_scam`.
- **System Prompts (3)**: `shieldcall_sentry`, `emergency_advisor`, `scam_investigator`.
