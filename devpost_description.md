# TriageForce: Autonomous Forensic Triage Agent for SANS SIFT

An autonomous incident response and forensic triage agent built to investigate compromised systems on a SANS SIFT Workstation. It utilizes the Google Gemini API and a custom Model Context Protocol (MCP) server to perform forensic analysis while preserving complete evidence integrity.

## What it does

TriageForce acts as an autonomous virtual forensic analyst that conducts end-to-end investigations on mounted forensic disk images. It connects to a remote SANS SIFT workstation, gathers and correlates historical and execution artifacts using **22 typed, read-only MCP tools**, builds an interactive timeline of events, validates findings against DFIR best practices, maps compromised artifacts to MITRE ATT&CK techniques, and outputs a complete, audit-logged forensic report.

Through a structured, self-correcting analyst loop, the agent avoids early conclusions and hallucinatory claims by challenging its own findings. When a tool fails or returns empty results, built-in **Forensic Pivot Rules** automatically redirect the agent to alternative tools within the same artifact class. Specifically, it can:
- **List and Hash Evidence**: Inspect case evidence directory file lists and calculate cryptographically secure hashes (SHA-256) of raw images.
- **Parse Execution Artifacts**: Extract program execution history by parsing Windows Prefetch files, Amcache, UserAssist, RecentApps, and the Application Compatibility Cache (ShimCache).
- **Inspect Event Logs**: Parse and query EVTX event logs (Security, System, Application) and operational logs (Sysmon, PowerShell script blocks) for suspicious executions, privilege assignments, and logon events.
- **Deep Filesystem Analysis**: Parse the $MFT Master File Table, USN Change Journal, Windows shortcut (.lnk) files, and Recycle Bin metadata for file activity reconstruction.
- **Registry Deep Dives**: Analyze SYSTEM, SAM, SOFTWARE, and SECURITY registry hives, extract service configurations, local user accounts, and aggregate all persistence/autorun locations.
- **Network and User Activity**: Analyze PCAP network captures with tshark filters and parse Chrome/Firefox/IE browser history databases.
- **Correlate and Verify Findings**: Automatically link disparate forensic logs (e.g. Sysmon execution events and ShimCache entries) to corroborate security claims and score confidence level.

## How we built it

TriageForce consists of two primary components communicating over a secure stdio JSON-RPC protocol tunnel:
1. **Local Forensic Client (`agent.py`)**: A Python client implementing a cognitive analyst loop leveraging the Google Gemini SDK. It manages the agentic workflow across distinct cognitive stages:
   - **`InvestigationPlanner`**: Formulates structured, hypothesis-driven plans before invoking remote SIFT tools.
   - **`EvidenceCorrelator`**: Collects findings in structured `EvidenceObject` formats and calculates dynamic confidence scores based on artifact source counts. Base scores range from `0.25` (single source) to `0.75` (3+ independent sources), with modifiers for successful/failed verifications (`+/-0.10`) and contradictions (`-0.15`).
   - **`DFIRValidator`**: Enforces strict industry best practices. It enforces a **0.40 hard threshold**, meaning any finding with a confidence score under `0.40` is blocked from transition to `verified` status and remains `inconclusive`.
   - **`ForensicTimeline`**: Normalizes all extracted timestamps to UTC, sorts events chronologically, and checks for logical timeline anomalies (e.g., file execution before file creation).
   - **`MitreAttackMapper`**: Maps parsed forensic findings directly to the tactics and techniques of the MITRE ATT&CK framework.
2. **Custom MCP Server (`server.py`)**: A Python-based Model Context Protocol server running on the remote SANS SIFT VM under root context. It exposes **22 typed, read-only tools** to the client. Rather than granting the agent a generic shell prompt (which introduces execution risk and commands that could modify evidence), it maps inputs to specific, read-only wrapper functions utilizing native SIFT forensic parsers like `PECmd`, `AmcacheParser`, `AppCompatCacheParser`, `RECmd`, `EvtxECmd`, `MFTECmd`, `LECmd`, `RBCmd`, `tshark`, and Python's `sqlite3` and `xml.etree` modules.

### Target Case Validation
To demonstrate the capabilities of TriageForce, we triaged a real-world compromised Windows XP disk image (`dmz-ftp-cdrive.E01`). The agent successfully reconstructed the attack chain with high confidence, identifying:
- **Credential Dumping**: Execution of `PWDumpX.exe`.
- **Lateral Movement**: Execution of `PsExec.exe` staged in the temporary folder `C:\Windows\Temp\perfmon\`.
- **Target User**: Compromise of local user `DMZ-FTP\rsydow`.
- **Execution & Defense Evasion**: PowerShell script execution downloading `Sysmon64.exe` to establish persistence and evade discovery, alongside `schtasks.exe` deleting scheduled tasks as `SYSTEM`.
- **Scale of Parsed Data**: 494 ShimCache entries parsed, 102 Security Event Log entries analyzed, and 13 Sysmon process creation events correlated.

## Challenges we ran into

- **API Rate Limits**: During initial validation, the Google Gemini API free-tier rate limits caused frequent `429 Resource Exhausted` exceptions, aborting long loops. We resolved this by implementing a localized retry mechanism with exponential backoff inside `agent.py` and introducing a 15-second inter-iteration delay to prevent aggressive requests.
- **Windows XP Artifact Availability**: The target image ran Windows XP. Since Windows XP predates the Amcache registry structure (`Amcache.hve`) and doesn't store Prefetch logs in the modern path structure, the agent had to gracefully handle missing artifacts, report them, and successfully rely on ShimCache (494 entries) and Security Event Logs to reconstruct the timeline.
- **E01 Mounting Complexity**: In SIFT, mounting E01 images programmatically while assuring complete read-only safety requires complex layering. We had to stage the raw disk file using `ewfmount`, map partitions, mount with `ntfs-3g`, and apply a read-only bind mount (`mount -o remount,ro,bind`) to guarantee that the agent has absolutely no write-capability to the underlying case directory.

## What we learned

- **Architectural Security is Key**: Relying on prompt engineering to keep an agent read-only is unsafe. By designing a custom MCP server that only exposes typed read-only wrappers, we created an unbreakable security boundary that prevents commands like `rm -rf` or file modification.
- **Corroboration Prevents Hallucination**: LLMs can easily assume that a program ran based on a single registry key. Forcing the agent to search for secondary corroborating artifacts (e.g., pairing a ShimCache modified timestamp with an EVTX log entry) dramatically reduces false-positive claims and elevates overall accuracy.
- **Time Normalization**: Merging timestamps from different event logs is challenging due to varying timezone configurations (UTC vs. local). Normalizing all timeline outputs to ISO 8601 UTC inside `ForensicTimeline` is essential to prevent chronological analysis failures.
- **Forensic Pivot Logic**: When a primary forensic parser fails (e.g. Prefetch not found on Windows XP), the agent must not abandon the artifact class entirely. Building pivot rules that redirect to alternative tools (e.g. $MFT for Prefetch, ShimCache for Amcache) ensures comprehensive coverage regardless of OS version limitations.
- **Environment Normalization**: Grounding the LLM on the canonical evidence root path at conversation start prevents path consistency warnings and tool invocation errors caused by the model guessing evidence mount locations.

## What's next

- **Memory Image Analysis**: Expose MCP tools wrapping Volatility 3 to let the agent analyze raw memory dumps alongside disk images.
- **Volume Shadow Copies (VSC)**: Integrate VSC parsing tools so the agent can automatically inspect historical versions of the registry and filesystem, identifying anti-forensics actions.
- **Live Endpoint Triage**: Adapt the Custom MCP Server to run on live endpoints (using osquery and event forwarding), allowing security teams to run TriageForce for automated, real-time triage.
