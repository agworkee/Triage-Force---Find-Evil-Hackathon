# Dataset Documentation: compromised SIFT Target Case

This document provides technical details of the forensic dataset investigated by the TriageForce agent, including artifact availability, specific findings, mount procedures, and limitations.

## Evidence Image

The target dataset consists of a forensic duplicate of a compromised Windows XP computer's C:\ drive, packaged in Expert Witness Format (EWF / E01).

- **File Name**: `dmz-ftp-cdrive.E01`
- **File Size**: ~25 GB (26,453,475,328 bytes)
- **Target OS**: Windows XP
- **Volume Name**: `Windows`
- **Volume Serial Number**: `6A12F21612F1E74B`
- **Mount Directory Path**: `/cases/case_001/evidence/`

---

## Artifact Availability

Due to the operating system version of the target (Windows XP), certain modern Windows forensic artifacts were unavailable, which the agent identified and adapted to:

| Artifact | Path Checked | Status | Details |
|---|---|---|---|
| **ShimCache** | `Windows/System32/config/SYSTEM` | ✅ PRESENT | **494 entries** parsed successfully by `AppCompatCacheParser`. Included cache position, execution status, and ControlSet configurations. |
| **Prefetch** | `Windows/Prefetch` | ❌ MISSING | **Not Present**: The Windows XP Prefetch directory was not found at the expected Windows 10/8 path configuration or was disabled on this system. |
| **Amcache** | `Windows/appcompat/Programs/Amcache.hve` | ❌ MISSING | **Not Present**: Windows XP predates the introduction of the Amcache registry structure (introduced in Windows 8). |
| **Sysmon EVTX** | `Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx` | ✅ PRESENT | **13 Process Creation events** (Event ID 1) parsed. Contained computer name `dmz-ftp`, PID, parent processes, and MD5 hashes. |
| **Security EVTX** | `Windows/System32/winevt/Logs/Security.evtx` | ✅ PRESENT | **102 entries** parsed. Targeted logon events (Event ID 4624) and process creations (Event ID 4688). |

---

## What the Agent Found

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

## Reproducibility Instructions

To mount the E01 file on a SIFT Workstation VM exactly as the agent expects, follow these instructions. 

### Staging the RAW Image
Use `ewfmount` (EWF-tools) to mount the E01 file as a raw raw-image filesystem:
```bash
# 1. Create the mount directory structure under cases
sudo mkdir -p /cases/case_001/image
sudo mkdir -p /cases/case_001/evidence
sudo mkdir -p /cases/case_001/mount

# 2. Stage the E01 image
# (Assuming dmz-ftp-cdrive.E01 has been copied to /cases/case_001/image/)
sudo ewfmount /cases/case_001/image/dmz-ftp-cdrive.E01 /cases/case_001/evidence
```
This stages a raw disk image file named `ewf1` (located at `/cases/case_001/evidence/ewf1`).

### Mounting the Partition using ntfs-3g
Next, mount the target NTFS partition from the raw `ewf1` file as read-only using `ntfs-3g`:
```bash
# 3. Mount the RAW partition (specifying loop, read-only status, and NTFS parameters)
sudo ntfs-3g -o ro,loop,show_sys_files,streams_interface=windows /cases/case_001/evidence/ewf1 /cases/case_001/mount

# 4. Perform a secure read-only bind mount to establish the TriageForce vault
sudo mount --bind /cases/case_001/mount /cases/case_001/evidence/
sudo mount -o remount,ro,bind /cases/case_001/evidence/
```

Confirm that the filesystem is read-only:
```bash
# This write attempt should fail with 'Read-only file system' error
sudo touch /cases/case_001/evidence/test.txt
```

---

## Known Limitations

- **Timezone Inconsistencies**: Windows XP ShimCache modified times do not always translate directly to UTC, depending on whether the system had active timezone offsets applied in control set configurations.
- **PowerShell Script Block Limitations**: On older OS levels, PowerShell script block logging (Event ID 4104) is restricted or not natively captured compared to Windows 10/Server 2016, limiting query results.
- **Registry Hives**: The agent is restricted to standard `RECmd` batch templates. Direct, custom registry queries outside the templates are blocked to prevent command injection, limiting deep registry carving.
