# Dataset Documentation: TriageForce Target Cases

This document provides technical details of the forensic datasets investigated by the TriageForce agent, including artifact availability, specific findings, mount procedures, and limitations.

---

## case_001 — DMZ FTP Server (Primary Validation)

### Evidence Image

| Field | Value |
|---|---|
| **File Name** | `dmz-ftp-cdrive.E01` |
| **File Size** | ~25 GB (26,453,475,328 bytes) |
| **Target OS** | Windows XP |
| **Volume Name** | `Windows` |
| **Volume Serial Number** | `6A12F21612F1E74B` |
| **Mount Path** | `/cases/case_001/evidence/` |
| **Validation Level** | Full agent triage with correlation report |

### Artifact Availability

Due to the operating system version of the target (Windows XP), certain modern Windows forensic artifacts were unavailable, which the agent identified and adapted to:

| Artifact | Path Checked | Status | Details |
|---|---|---|---|
| **ShimCache** | `Windows/System32/config/SYSTEM` | ✅ PRESENT | **494 entries** parsed successfully by `AppCompatCacheParser`. Included cache position, execution status, and ControlSet configurations. |
| **Prefetch** | `Windows/Prefetch` | ❌ MISSING | **Not Present**: The Windows XP Prefetch directory was not found at the expected configuration or was disabled on this system. |
| **Amcache** | `Windows/appcompat/Programs/Amcache.hve` | ❌ MISSING | **Not Present**: Windows XP predates the introduction of the Amcache registry structure (introduced in Windows 8). |
| **Sysmon EVTX** | `Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx` | ✅ PRESENT | **13 Process Creation events** (Event ID 1) parsed. Contained computer name `dmz-ftp`, PID, parent processes, and MD5 hashes. |
| **Security EVTX** | `Windows/System32/winevt/Logs/Security.evtx` | ✅ PRESENT | **102 entries** parsed. Targeted logon events (Event ID 4624) and process creations (Event ID 4688). |
| **$MFT** | `$MFT` | ✅ PRESENT | Master File Table parsed via `MFTECmd`. Contains full filesystem metadata including timestamps, entry numbers, and file sizes. |
| **SYSTEM Hive** | `Windows/System32/config/SYSTEM` | ✅ PRESENT | Registry hive parsed via `RECmd`. Services and ControlSet configurations extracted. |
| **SAM Hive** | `Windows/System32/config/SAM` | ✅ PRESENT | Local user accounts and RIDs extracted via `RECmd`. |
| **SOFTWARE Hive** | `Windows/System32/config/SOFTWARE` | ✅ PRESENT | Registry Run keys and installed software entries parsed via `RECmd`. |
| **Scheduled Tasks** | `Windows/System32/Tasks` | ⚠️ PARTIAL | Task XML definitions parsed where present. Windows XP used `.job` format which is not covered by the XML parser. |
| **$Recycle.Bin** | `$Recycle.Bin` | ⚠️ PARTIAL | Recycle Bin metadata parsed via `RBCmd`. Windows XP may use `RECYCLER` instead of `$Recycle.Bin`. |

### What the Agent Found

By correlating the available ShimCache, Sysmon, and Security logs, TriageForce reconstructed the following key attack timeline and findings from the execution log `agent_execution.jsonl`:

1. **Staged Execution (Lateral Movement)**:
   - **Artifact**: ShimCache & Sysmon (Event ID 1)
   - **Finding**: Execution of the Sysinternals lateral movement tool `PsExec.exe` located at a suspicious temporary staging directory path: `C:\Windows\Temp\perfmon\PsExec.exe`.
   - **Timestamp**: correlated with execution at `2018-08-07 19:06:03.0182792`.
2. **Credential Harvesting**:
   - **Artifact**: ShimCache & EVTX Logs
   - **Finding**: Execution of the credential dumping utility `PWDumpX.exe` (and related DLL dependencies) designed to extract password hashes from memory/registry.
3. **Target Compromised User Account**:
   - **Artifact**: Security Event Log (Event ID 4624)
   - **Finding**: Logon activity matching the local account `DMZ-FTP\rsydow`. The compromise of this specific user account facilitated further lateral movement.
4. **Defense Evasion and System Tampering**:
   - **Artifact**: Sysmon Event Log & PowerShell Logs
   - **Finding**: PowerShell command execution downloading `Sysmon64.exe` to establish persistence/evade discovery, combined with `schtasks.exe` commands deleting scheduled tasks under the context of `SYSTEM` user to cover tracks and remove administrative monitors.

---

## case_002 — Domain Controller (Generalization Validation)

### Evidence Image

| Field | Value |
|---|---|
| **File Name** | `base-dc-cdrive.E01` |
| **File Size** | ~11.48 GB (12,325,692,793 bytes) |
| **Target OS** | Windows Server (observed DC role) |
| **SHA256** | `e2b9cf0cb6759fd079f45fa903d80bde602160ff969c969c6f0cd704965b31b1` |
| **Mount Path** | `/cases/case_002/evidence/` |
| **Validation Level** | Artifact-verified (mounted, artifacts confirmed present; full agent triage not yet executed) |

### Artifact Availability

The following artifacts were observed during mount verification. Their presence was confirmed via filesystem inspection; tool output has not yet been fully parsed by the agent.

| Artifact | Path Observed | Status | Details |
|---|---|---|---|
| **NTDS.dit** | `Windows/NTDS/ntds.dit` | ✅ PRESENT | Active Directory database — confirms this image is a Domain Controller. |
| **SYSTEM Hive** | `Windows/System32/config/SYSTEM` | ✅ PRESENT | Registry hive available for ShimCache and service parsing. |
| **SAM Hive** | `Windows/System32/config/SAM` | ✅ PRESENT | Local user accounts available. |
| **SECURITY Hive** | `Windows/System32/config/SECURITY` | ✅ PRESENT | Security policy and cached credentials available. |
| **SOFTWARE Hive** | `Windows/System32/config/SOFTWARE` | ✅ PRESENT | Registry Run keys and installed software available. |
| **Security EVTX** | `Windows/System32/winevt/Logs/Security.evtx` | ✅ PRESENT | Security event log available for logon and process creation analysis. |
| **System EVTX** | `Windows/System32/winevt/Logs/System.evtx` | ✅ PRESENT | System event log available. |
| **Directory Service EVTX** | `Windows/System32/winevt/Logs/Directory Service.evtx` | ✅ PRESENT | DC-specific log; supported by extended `analyze_evtx` tool. |
| **DNS Server EVTX** | `Windows/System32/winevt/Logs/DNS Server.evtx` | ✅ PRESENT | DC-specific log; supported by extended `analyze_evtx` tool. |
| **DFS Replication EVTX** | `Windows/System32/winevt/Logs/DFS Replication.evtx` | ✅ PRESENT | DC-specific log; supported by extended `analyze_evtx` tool. |
| **Group Policy** | `Windows/SYSVOL/` | ✅ PRESENT | Group Policy Objects directory observed. |
| **$MFT** | `$MFT` | ✅ PRESENT | Master File Table available for filesystem metadata analysis. |
| **Prefetch** | `Windows/Prefetch` | ⚠️ NOT VERIFIED | Prefetch may be disabled on Server OS by default. |
| **Amcache** | `Windows/appcompat/Programs/Amcache.hve` | ⚠️ NOT VERIFIED | Presence depends on Windows Server version. |

> **Note**: case_002 has been artifact-verified (all artifacts confirmed present via `ls` and `analyze_domain_controller_artifacts` tool output) but has not undergone a full agent triage loop. Findings from a full investigation run are pending.

---

## Reproducibility Instructions

To mount the E01 files on a SIFT Workstation VM exactly as the agent expects, follow these instructions.

### case_001 — DMZ FTP Server

```bash
# 1. Create the mount directory structure
sudo mkdir -p /cases/case_001/image
sudo mkdir -p /cases/case_001/evidence
sudo mkdir -p /cases/case_001/mount

# 2. Stage the E01 image (copy dmz-ftp-cdrive.E01 to /cases/case_001/image/)
sudo ewfmount /cases/case_001/image/dmz-ftp-cdrive.E01 /cases/case_001/evidence

# 3. Mount the underlying NTFS partition read-only
sudo ntfs-3g -o ro,loop,show_sys_files,streams_interface=windows /cases/case_001/evidence/ewf1 /cases/case_001/mount

# 4. Perform a read-only bind mount to establish the TriageForce evidence vault
sudo mount --bind /cases/case_001/mount /cases/case_001/evidence/
sudo mount -o remount,ro,bind /cases/case_001/evidence/
```

### case_002 — Domain Controller

```bash
# 1. Create the mount directory structure
sudo mkdir -p /cases/case_002/raw
sudo mkdir -p /cases/case_002/ewf
sudo mkdir -p /cases/case_002/evidence

# 2. Copy base-dc-cdrive.E01 to /cases/case_002/raw/
sudo ewfmount /cases/case_002/raw/base-dc-cdrive.E01 /cases/case_002/ewf

# 3. Mount the underlying NTFS partition read-only
sudo mount -o ro,loop,show_sys_files /cases/case_002/ewf/ewf1 /cases/case_002/evidence
```

### Verify Read-Only Mount

Confirm that the filesystem is read-only for both cases:
```bash
# These write attempts should fail with 'Read-only file system' error
sudo touch /cases/case_001/evidence/test.txt
sudo touch /cases/case_002/evidence/test.txt
```

---

## Running the Agent Against Each Case

```bash
# case_001 (default — no --case-id flag needed)
python agent.py --task "Perform full forensic triage on case_001"

# case_002 (requires --case-id flag)
python agent.py --case-id case_002 --task "Perform full forensic triage on case_002"
```

---

## Known Limitations

- **Timezone Inconsistencies**: Windows XP ShimCache modified times do not always translate directly to UTC, depending on whether the system had active timezone offsets applied in control set configurations.
- **PowerShell Script Block Limitations**: On older OS levels, PowerShell script block logging (Event ID 4104) is restricted or not natively captured compared to Windows 10/Server 2016, limiting query results.
- **Registry Hives**: The agent supports parsing of SYSTEM, SAM, SOFTWARE, and SECURITY hives via `RECmd`, plus per-user NTUSER.DAT hives. Custom registry queries outside the supported key paths are blocked to prevent command injection.
- **Forensic Pivot Coverage**: The agent's pivot rules cover the 4 most common artifact class failures (Prefetch, Amcache, EVTX, Sysmon). Additional pivots for less common failures (e.g. LNK → MFT, RecycleBin → USN Journal) may be added in future iterations.
- **case_002 Coverage**: The domain controller image has been mounted and its artifacts verified, but a full agent triage loop has not yet been executed against it. All findings for case_002 are limited to artifact presence confirmation.
