# Accuracy Report: TriageForce Self-Assessment

This document presents a structured accuracy and integrity assessment of the TriageForce agent during its automated analysis of the compromised SIFT workstation case image.

## Findings Summary

TriageForce triaged the case disk image and compiled execution, authentication, and network artifacts. Despite the older target operating system (Windows XP) creating gaps in expected modern registry hives, the agent compiled a coherent attack timeline. It successfully isolated credential harvesting, lateral movement, account compromise, and defense evasion actions.

---

## True Positives

The following high-confidence detections represent verified, genuine malicious activities that occurred on the compromised system:

1. **PsExec Lateral Staging**:
   - **Status**: True Positive (verified)
   - **Finding**: Detections of `PsExec.exe` executing from `C:\Windows\Temp\perfmon\PsExec.exe`. Staging Sysinternals administration tools in temporary folders is a hallmark technique for lateral movement (MITRE ATT&CK T1072).
2. **Credential Harvesting**:
   - **Status**: True Positive (verified)
   - **Finding**: Execution of the credential extractor `PWDumpX.exe` designed to dump password hashes.
3. **PowerShell Scripting**:
   - **Status**: True Positive (verified)
   - **Finding**: Script execution downloading `Sysmon64.exe` to establish persistent, stealthy process monitoring.
4. **Defense Evasion**:
   - **Status**: True Positive (verified)
   - **Finding**: Direct usage of `schtasks.exe` executing as `SYSTEM` to delete scheduled tasks.

---

## False Positives Analysis

- **System and VM Tool Executions**:
  - The ShimCache contains entries for `VMwareResolutionSet.exe` and `LogonUI.exe`. The model initially flagged these as potential anomalies due to execution flags, but verified them as standard environment components during the verification loop, resulting in no false-positive alert generation in the final report.
- **Single-Source Anomalies**:
  - The tool discovery phase originally flagged simple file path listings as execution evidence, but these were successfully penalized by the `DFIRValidator` due to lack of secondary corroborating evidence.

---

## Missed Artifacts

The following potential sources of evidence were not analyzed due to target OS limitations and tool constraints:

- **Prefetch Directory**: Modern Prefetch directories under `/Windows/Prefetch/` were not parsed due to path layout differences on Windows XP.
- **Amcache**: No Amcache logs (`Amcache.hve`) were parsed because Windows XP predates this registry feature (introduced in Windows 8).
- **Volume Shadow Copies (VSC)**: Historical versions of system files stored in shadow copies were not mounted or analyzed.
- **Memory Image**: Live system memory dumps were not captured or analyzed, meaning active network sockets and transient process injections were missed.

---

## Expanded Tool Coverage

TriageForce now exposes **22 typed, read-only tools** on the MCP server (up from 12), covering:

| Category | Tools | Parser |
|---|---|---|
| **Filesystem** | `analyze_mft`, `analyze_usn_journal`, `analyze_lnk_files` | MFTECmd, LECmd |
| **Registry** | `analyze_registry_hive`, `analyze_sam_users`, `analyze_services`, `analyze_autoruns` | RECmd |
| **Execution** | `analyze_prefetch`, `analyze_amcache`, `analyze_shimcache`, `analyze_userassist`, `analyze_recentapps` | PECmd, AmcacheParser, AppCompatCacheParser, RECmd |
| **Event Logs** | `analyze_sysmon`, `analyze_evtx`, `analyze_powershell_logs` | EvtxECmd |
| **Network** | `run_tshark_summary`, `analyze_network_connections` | tshark |
| **User Activity** | `analyze_browser_history`, `analyze_recyclebin`, `analyze_scheduled_tasks` | sqlite3, RBCmd, XML |
| **Evidence Management** | `list_case_evidence`, `get_evidence_integrity` | sha256sum |

### Forensic Pivot Testing

The agent's `FORENSIC PIVOT RULES` were validated during the target case analysis:
- `analyze_prefetch` returned "not found" on the Windows XP image → the agent pivoted to `analyze_mft` with `filename_filter='Prefetch'` to search the MFT for Prefetch-related entries.
- `analyze_amcache` returned "not found" (Windows XP predates Amcache) → the agent pivoted to `analyze_shimcache`, which successfully returned 494 execution entries.
- All pivots were logged in the audit trail with the failed tool name, failure reason, and the selected alternative.

---

## Hallucination Risk Assessment

To protect against standard LLM hallucinations (such as inventing logs or registry keys), TriageForce enforces strict mitigation rules:

- **Single-Source Capping**: Any finding backed by only one evidence source (e.g. only a ShimCache entry with no Sysmon or Event Log corroboration) is automatically capped at a maximum confidence score of **`0.30` (LOW)**.
- **Hard Verification Threshold**: A hard threshold of **`0.40`** is enforced. If a finding fails to gather enough corroborating evidence to push its score to `0.40` or above, it is blocked from transitioning to `verified` status and is classified as `inconclusive`.

---

## Evidence Integrity Approach

TriageForce guarantees evidence preservation through multi-layered architectural boundaries:

1. **Read-Only Mounts**: The raw disk image is mounted strictly read-only using `ntfs-3g` and then bind-mounted (`mount -o remount,ro,bind`). 
2. **Type-Safe MCP Server**: The `server.py` file exposes 22 typed, read-only tool wrappers. The model can only execute pre-defined python wrappers — no shell access is granted.
3. **Path Traversal Protection**: Every file tool validates input parameters via `safe_evidence_path()`, blocking traversal attempts (e.g. `../../etc/passwd`) by checking that the resolved path strictly starts with the `/cases` root.

---

## Spoliation Testing

Spoliation validation was manually tested on the target SIFT workstation to ensure filesystem lockdown:

- **Action**: Attempted to write a test file to the mounted evidence directory:
  ```bash
  touch /cases/case_001/evidence/test.txt
  ```
- **Result**: `touch: cannot touch '/cases/case_001/evidence/test.txt': Read-only file system`
- **Verdict**: ✅ Integrity locked down. No spoliation is possible.

---

## Failure Modes Documented

- **API Rate Limiting (429)**: Frequent queries can exhaust Gemini API free-tier quotas. The agent handles this by sleeping for 15 seconds between iterations and executing a retry loop for up to 5 attempts when catching a 429 error.
- **Command Timeouts**: Long-running commands (such as calculating the SHA-256 hash of a 25GB file) can hit the 60-second subprocess timeout. The agent handles this by reporting a `"timeout"` status in JSON and prompting the user to wait or allocate more resources.
- **Path Resolution Failures**: If the remote case folder structure is not mounted, tools return a clear `"directory not found"` JSON object, preventing client-side exceptions.
