import os
import sys
import json
import subprocess
import shlex
import logging
import glob
import csv
import io
from typing import Dict, Any, List, Optional
from mcp.server.fastmcp import FastMCP

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("triageforce")

# Initialize FastMCP Server
mcp = FastMCP("TriageForce")

# Constant definitions
EVIDENCE_BASE_DIR = "/cases"

# ---------------------------------------------------------------------------
# Well-known Windows artifact paths relative to a mounted NTFS volume
# ---------------------------------------------------------------------------
ARTIFACT_PATHS = {
    "prefetch": "Windows/Prefetch",
    "amcache": "Windows/appcompat/Programs/Amcache.hve",
    "shimcache": "Windows/System32/config/SYSTEM",
    "userassist": "NTUSER.DAT",                     # per-user; searched under Users/
    "recentapps": "NTUSER.DAT",                      # same hive, different key
    "sysmon": "Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
    "evtx_security": "Windows/System32/winevt/Logs/Security.evtx",
    "evtx_system": "Windows/System32/winevt/Logs/System.evtx",
    "evtx_application": "Windows/System32/winevt/Logs/Application.evtx",
    "powershell_operational": "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx",
    "powershell_scriptblock": "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx",
    "usn_journal": "$Extend/$UsnJrnl:$J",
}


def run_local_command(args: List[str], timeout: int = 60) -> Dict[str, Any]:
    """
    Safely executes a system command and returns structured JSON output.
    All execution parameters are validated to prevent command injection.
    """
    logger.info(f"Running command: {' '.join(args)}")
    try:
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False
        )
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "status": "success" if result.returncode == 0 else "failed"
        }
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(args)}")
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "Command timed out after {} seconds".format(timeout),
            "status": "timeout"
        }
    except Exception as e:
        logger.error(f"Error running command: {str(e)}")
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": str(e),
            "status": "error"
        }


def safe_evidence_path(case_id: str, relative: str) -> Optional[str]:
    """
    Resolve an evidence path safely, preventing directory traversal.
    Returns the normalized absolute path or None on violation.
    """
    safe = os.path.normpath(os.path.join(EVIDENCE_BASE_DIR, case_id, "evidence", relative))
    if not safe.startswith(EVIDENCE_BASE_DIR):
        return None
    return safe


def _parse_csv_output(stdout: str, max_rows: int = 500) -> List[Dict[str, str]]:
    """
    Parse CSV-formatted tool output into a list of dicts.
    Many SIFT/EZ-Tools emit CSV; this centralizes parsing.
    """
    rows: List[Dict[str, str]] = []
    reader = csv.DictReader(io.StringIO(stdout))
    for i, row in enumerate(reader):
        if i >= max_rows:
            break
        rows.append(dict(row))
    return rows


def _find_files(base_dir: str, pattern: str) -> List[str]:
    """
    Recursively find files matching a glob pattern under base_dir.
    Returns absolute paths.  Read-only; no modifications.
    """
    results = glob.glob(os.path.join(base_dir, "**", pattern), recursive=True)
    return sorted(results)


# ===================================================================
# EXISTING TOOLS — unchanged
# ===================================================================

@mcp.tool()
def get_evidence_integrity(case_id: str, file_path: str) -> str:
    """
    Exposes sha256 checksum logic to verify file integrity on the remote SIFT workstation.
    This prevents evidence spoliation.
    """
    # Ensure safe path structure to prevent directory traversal
    safe_path = os.path.normpath(os.path.join(EVIDENCE_BASE_DIR, case_id, "evidence", file_path))
    if not safe_path.startswith(EVIDENCE_BASE_DIR):
        return json.dumps({"error": "Path traversal detected"})
        
    if not os.path.exists(safe_path):
        return json.dumps({"error": f"Evidence file not found: {file_path}"})
        
    res = run_local_command(["sha256sum", safe_path], timeout=300)
    if res["status"] == "success":
        parts = res["stdout"].strip().split()
        if parts:
            return json.dumps({"sha256": parts[0], "file": file_path})
    return json.dumps({"error": f"Failed to compute hash: {res['stderr']}"})

@mcp.tool()
def run_tshark_summary(case_id: str, pcap_name: str, max_conversations: int = 50) -> str:
    """
    Runs tshark analysis on a specific pcap file and structures the output.
    """
    safe_path = os.path.normpath(os.path.join(EVIDENCE_BASE_DIR, case_id, "evidence", pcap_name))
    if not safe_path.startswith(EVIDENCE_BASE_DIR):
        return json.dumps({"error": "Path traversal detected"})
        
    if not os.path.exists(safe_path):
        return json.dumps({"error": f"PCAP file not found: {pcap_name}"})
        
    # Example command to extract protocol hierarchy summary
    cmd = ["tshark", "-r", safe_path, "-q", "-z", "io,phs"]
    res = run_local_command(cmd, timeout=30)
    
    if res["status"] == "success":
        return json.dumps({
            "pcap": pcap_name,
            "protocol_hierarchy": res["stdout"].strip(),
            "error": None
        })
    else:
        return json.dumps({
            "pcap": pcap_name,
            "protocol_hierarchy": None,
            "error": res["stderr"]
        })

@mcp.tool()
def list_case_evidence(case_id: str) -> str:
    """
    Lists evidence files available in a case directory safely.
    """
    case_path = os.path.normpath(os.path.join(EVIDENCE_BASE_DIR, case_id, "evidence"))
    if not case_path.startswith(EVIDENCE_BASE_DIR):
        return json.dumps({"error": "Path traversal detected"})
        
    if not os.path.exists(case_path):
        return json.dumps({"error": f"Case directory not found: {case_id}"})
        
    try:
        files = []
        for entry in os.scandir(case_path):
            files.append({
                "name": entry.name,
                "is_dir": entry.is_dir(),
                "size": entry.stat().st_size if entry.is_file() else 0
            })
        return json.dumps({"case_id": case_id, "files": files})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ===================================================================
# NEW ANALYSIS TOOLS — read-only DFIR artifact analysis
# ===================================================================

@mcp.tool()
def analyze_prefetch(case_id: str, executable_filter: str = "") -> str:
    """
    Analyze Windows Prefetch files from the evidence image.

    Parses all .pf files under Windows/Prefetch using PECmd (SIFT-native).
    Returns structured JSON with executable names, run counts, last-run
    timestamps, and referenced file paths.

    Args:
        case_id: The case identifier (e.g. 'case_001').
        executable_filter: Optional substring to filter results by executable name.

    Returns:
        Structured JSON with artifact_source, timestamps, and parsed entries.
    """
    evidence_dir = safe_evidence_path(case_id, "")
    if evidence_dir is None:
        return json.dumps({"error": "Path traversal detected"})

    prefetch_dir = safe_evidence_path(case_id, ARTIFACT_PATHS["prefetch"])
    if prefetch_dir is None:
        return json.dumps({"error": "Path traversal detected"})

    if not os.path.isdir(prefetch_dir):
        return json.dumps({
            "error": f"Prefetch directory not found at {ARTIFACT_PATHS['prefetch']}",
            "artifact_source": "prefetch",
            "case_id": case_id,
        })

    # PECmd.exe (Eric Zimmerman) is pre-installed on SIFT at /usr/local/bin
    # --csv outputs structured CSV;  -d specifies the directory of .pf files
    cmd = [
        "PECmd", "-d", prefetch_dir,
        "--csv", "/tmp", "--csvf", "prefetch_output.csv", "-q"
    ]
    res = run_local_command(cmd, timeout=120)

    csv_path = "/tmp/prefetch_output.csv"
    entries: List[Dict[str, Any]] = []

    if res["status"] == "success" and os.path.exists(csv_path):
        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                rows = _parse_csv_output(f.read(), max_rows=500)
            for row in rows:
                entry = {
                    "executable": row.get("ExecutableName", row.get("SourceFilename", "")),
                    "run_count": row.get("RunCount", ""),
                    "last_run": row.get("LastRun", row.get("PreviousRun0", "")),
                    "previous_runs": [
                        row.get(f"PreviousRun{i}", "") for i in range(1, 8)
                        if row.get(f"PreviousRun{i}", "")
                    ],
                    "volume_path": row.get("Volume0Name", ""),
                    "file_size": row.get("Size", ""),
                    "source_file": row.get("SourceFilename", ""),
                }
                if executable_filter:
                    if executable_filter.lower() not in entry["executable"].lower():
                        continue
                entries.append(entry)
        except Exception as e:
            logger.error(f"Error parsing prefetch CSV: {e}")
            return json.dumps({
                "error": f"CSV parse error: {str(e)}",
                "artifact_source": "prefetch",
                "case_id": case_id,
                "raw_stderr": res.get("stderr", ""),
            })
        finally:
            # Clean up temp CSV
            if os.path.exists(csv_path):
                os.remove(csv_path)
    else:
        # Fallback: list .pf files with metadata if PECmd is unavailable
        pf_files = _find_files(prefetch_dir, "*.pf")
        for pf in pf_files:
            stat = os.stat(pf)
            entries.append({
                "executable": os.path.basename(pf).rsplit("-", 1)[0] if "-" in os.path.basename(pf) else os.path.basename(pf),
                "file_name": os.path.basename(pf),
                "file_size": stat.st_size,
                "modified_time": str(stat.st_mtime),
                "note": "Raw file listing — PECmd parser unavailable",
            })
        if executable_filter:
            entries = [e for e in entries if executable_filter.lower() in e.get("executable", "").lower()]

    return json.dumps({
        "artifact_source": "prefetch",
        "case_id": case_id,
        "artifact_path": ARTIFACT_PATHS["prefetch"],
        "total_entries": len(entries),
        "entries": entries,
        "parser": "PECmd" if res["status"] == "success" else "file_metadata_fallback",
        "status": "success" if entries else "no_results",
    })


@mcp.tool()
def analyze_amcache(case_id: str, executable_filter: str = "") -> str:
    """
    Analyze the Amcache.hve registry hive for program execution evidence.

    Parses the Amcache using AmcacheParser (Eric Zimmerman / SIFT-native).
    Returns structured JSON with SHA1 hashes, file paths, publisher info,
    and first-run timestamps.

    Args:
        case_id: The case identifier.
        executable_filter: Optional substring to filter by file name.

    Returns:
        Structured JSON with artifact_source, timestamps, and parsed entries.
    """
    amcache_path = safe_evidence_path(case_id, ARTIFACT_PATHS["amcache"])
    if amcache_path is None:
        return json.dumps({"error": "Path traversal detected"})

    if not os.path.exists(amcache_path):
        return json.dumps({
            "error": f"Amcache.hve not found at {ARTIFACT_PATHS['amcache']}",
            "artifact_source": "amcache",
            "case_id": case_id,
        })

    cmd = [
        "AmcacheParser", "-f", amcache_path,
        "--csv", "/tmp", "--csvf", "amcache_output.csv", "-i"
    ]
    res = run_local_command(cmd, timeout=120)

    # AmcacheParser writes multiple CSVs; the unassociated file entries are most useful
    csv_candidates = [
        "/tmp/amcache_output.csv",
        "/tmp/amcache_output_UnassociatedFileEntries.csv",
        "/tmp/amcache_output_FileEntries.csv",
    ]

    entries: List[Dict[str, Any]] = []
    used_csv = None
    for csv_path in csv_candidates:
        if os.path.exists(csv_path):
            used_csv = csv_path
            try:
                with open(csv_path, "r", encoding="utf-8-sig") as f:
                    rows = _parse_csv_output(f.read(), max_rows=500)
                for row in rows:
                    entry = {
                        "file_name": row.get("FileName", row.get("Name", "")),
                        "full_path": row.get("FullPath", row.get("FilePath", "")),
                        "sha1": row.get("SHA1", row.get("FileId", "")),
                        "publisher": row.get("Publisher", ""),
                        "product_name": row.get("ProductName", ""),
                        "file_version": row.get("FileVersion", ""),
                        "file_size": row.get("Size", row.get("FileSize", "")),
                        "link_date": row.get("LinkDate", ""),
                        "first_run": row.get("FileKeyLastWriteTimestamp",
                                              row.get("LastWriteTimestamp", "")),
                        "pe_header_hash": row.get("PeHeaderHash", ""),
                    }
                    if executable_filter:
                        name = entry.get("file_name", "") + entry.get("full_path", "")
                        if executable_filter.lower() not in name.lower():
                            continue
                    entries.append(entry)
            except Exception as e:
                logger.error(f"Error parsing amcache CSV {csv_path}: {e}")
            break  # use first available CSV

    # Clean up temp files
    for csv_path in csv_candidates:
        if os.path.exists(csv_path):
            try:
                os.remove(csv_path)
            except OSError:
                pass

    return json.dumps({
        "artifact_source": "amcache",
        "case_id": case_id,
        "artifact_path": ARTIFACT_PATHS["amcache"],
        "total_entries": len(entries),
        "entries": entries,
        "parser": "AmcacheParser",
        "csv_source": os.path.basename(used_csv) if used_csv else None,
        "status": "success" if entries else ("parser_error" if res["status"] != "success" else "no_results"),
        "parser_stderr": res.get("stderr", "")[:300] if res["status"] != "success" else "",
    })


@mcp.tool()
def analyze_shimcache(case_id: str, executable_filter: str = "") -> str:
    """
    Analyze the Application Compatibility Cache (ShimCache) from the SYSTEM hive.

    Parses using AppCompatCacheParser (Eric Zimmerman / SIFT-native).
    Returns structured JSON with executable paths, last-modified times,
    and cache entry positions.

    Args:
        case_id: The case identifier.
        executable_filter: Optional substring to filter by path.

    Returns:
        Structured JSON with artifact_source, timestamps, and parsed entries.
    """
    system_hive = safe_evidence_path(case_id, ARTIFACT_PATHS["shimcache"])
    if system_hive is None:
        return json.dumps({"error": "Path traversal detected"})

    if not os.path.exists(system_hive):
        return json.dumps({
            "error": f"SYSTEM hive not found at {ARTIFACT_PATHS['shimcache']}",
            "artifact_source": "shimcache",
            "case_id": case_id,
        })

    csv_path = "/tmp/shimcache_output.csv"
    cmd = [
        "AppCompatCacheParser", "-f", system_hive,
        "--csv", "/tmp", "--csvf", "shimcache_output.csv"
    ]
    res = run_local_command(cmd, timeout=120)

    entries: List[Dict[str, Any]] = []
    if os.path.exists(csv_path):
        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                rows = _parse_csv_output(f.read(), max_rows=500)
            for idx, row in enumerate(rows):
                entry = {
                    "cache_position": idx,
                    "path": row.get("Path", row.get("CachePath", "")),
                    "last_modified_time": row.get("LastModifiedTimeUTC",
                                                   row.get("LastModified", "")),
                    "executed_flag": row.get("Executed", ""),
                    "data_size": row.get("DataSize", ""),
                    "controlset": row.get("ControlSet", ""),
                }
                if executable_filter:
                    if executable_filter.lower() not in entry["path"].lower():
                        continue
                entries.append(entry)
        except Exception as e:
            logger.error(f"Error parsing shimcache CSV: {e}")
        finally:
            if os.path.exists(csv_path):
                os.remove(csv_path)

    return json.dumps({
        "artifact_source": "shimcache",
        "case_id": case_id,
        "artifact_path": ARTIFACT_PATHS["shimcache"],
        "total_entries": len(entries),
        "entries": entries,
        "parser": "AppCompatCacheParser",
        "status": "success" if entries else ("parser_error" if res["status"] != "success" else "no_results"),
        "parser_stderr": res.get("stderr", "")[:300] if res["status"] != "success" else "",
    })


@mcp.tool()
def analyze_userassist(case_id: str, username: str = "", executable_filter: str = "") -> str:
    """
    Analyze UserAssist registry keys from NTUSER.DAT hives.

    Parses using RECmd (Eric Zimmerman / SIFT-native) with the UserAssist
    batch file. Returns structured JSON with program names, run counts,
    focus times, and last-execution timestamps.

    Args:
        case_id: The case identifier.
        username: Optional username to target a specific user profile.
        executable_filter: Optional substring to filter by program name.

    Returns:
        Structured JSON with artifact_source, timestamps, and parsed entries.
    """
    evidence_dir = safe_evidence_path(case_id, "")
    if evidence_dir is None:
        return json.dumps({"error": "Path traversal detected"})

    # Find NTUSER.DAT files
    users_dir = os.path.join(evidence_dir, "Users")
    ntuser_files: List[str] = []

    if os.path.isdir(users_dir):
        for user_entry in os.scandir(users_dir):
            if user_entry.is_dir():
                if username and username.lower() != user_entry.name.lower():
                    continue
                ntuser = os.path.join(user_entry.path, "NTUSER.DAT")
                if os.path.exists(ntuser):
                    ntuser_files.append(ntuser)

    if not ntuser_files:
        return json.dumps({
            "error": "No NTUSER.DAT files found" + (f" for user '{username}'" if username else ""),
            "artifact_source": "userassist",
            "case_id": case_id,
        })

    all_entries: List[Dict[str, Any]] = []
    for ntuser_path in ntuser_files:
        # Extract username from path
        user = os.path.basename(os.path.dirname(ntuser_path))
        csv_path = f"/tmp/userassist_{user}.csv"

        cmd = [
            "RECmd", "-f", ntuser_path,
            "--bn", "/usr/local/bin/BatchExamples/UserAssist.reb",
            "--csv", "/tmp", "--csvf", f"userassist_{user}.csv"
        ]
        res = run_local_command(cmd, timeout=120)

        if os.path.exists(csv_path):
            try:
                with open(csv_path, "r", encoding="utf-8-sig") as f:
                    rows = _parse_csv_output(f.read(), max_rows=300)
                for row in rows:
                    entry = {
                        "username": user,
                        "program_name": row.get("ValueName", row.get("ValueData", "")),
                        "run_count": row.get("RunCount", row.get("Count", "")),
                        "last_executed": row.get("LastExecuted",
                                                  row.get("LastRun", "")),
                        "focus_count": row.get("FocusCount", ""),
                        "focus_time_seconds": row.get("FocusTime", ""),
                        "hive_path": ntuser_path,
                    }
                    if executable_filter:
                        if executable_filter.lower() not in entry["program_name"].lower():
                            continue
                    all_entries.append(entry)
            except Exception as e:
                logger.error(f"Error parsing UserAssist CSV for {user}: {e}")
            finally:
                if os.path.exists(csv_path):
                    os.remove(csv_path)

    return json.dumps({
        "artifact_source": "userassist",
        "case_id": case_id,
        "users_analyzed": [os.path.basename(os.path.dirname(p)) for p in ntuser_files],
        "total_entries": len(all_entries),
        "entries": all_entries,
        "parser": "RECmd",
        "status": "success" if all_entries else "no_results",
    })


@mcp.tool()
def analyze_recentapps(case_id: str, username: str = "") -> str:
    """
    Analyze RecentApps registry keys from NTUSER.DAT hives.

    Parses the RecentApps subkeys under the User Assist area of NTUSER.DAT
    using RECmd.  Returns structured JSON with application names, launch
    counts, and last-access timestamps.

    Args:
        case_id: The case identifier.
        username: Optional username to target a specific user profile.

    Returns:
        Structured JSON with artifact_source, timestamps, and parsed entries.
    """
    evidence_dir = safe_evidence_path(case_id, "")
    if evidence_dir is None:
        return json.dumps({"error": "Path traversal detected"})

    users_dir = os.path.join(evidence_dir, "Users")
    ntuser_files: List[str] = []

    if os.path.isdir(users_dir):
        for user_entry in os.scandir(users_dir):
            if user_entry.is_dir():
                if username and username.lower() != user_entry.name.lower():
                    continue
                ntuser = os.path.join(user_entry.path, "NTUSER.DAT")
                if os.path.exists(ntuser):
                    ntuser_files.append(ntuser)

    if not ntuser_files:
        return json.dumps({
            "error": "No NTUSER.DAT files found" + (f" for user '{username}'" if username else ""),
            "artifact_source": "recentapps",
            "case_id": case_id,
        })

    all_entries: List[Dict[str, Any]] = []
    for ntuser_path in ntuser_files:
        user = os.path.basename(os.path.dirname(ntuser_path))
        csv_path = f"/tmp/recentapps_{user}.csv"

        # Use RECmd with a key path targeting RecentApps
        cmd = [
            "RECmd", "-f", ntuser_path,
            "--kn", "Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps",
            "--csv", "/tmp", "--csvf", f"recentapps_{user}.csv"
        ]
        res = run_local_command(cmd, timeout=120)

        if os.path.exists(csv_path):
            try:
                with open(csv_path, "r", encoding="utf-8-sig") as f:
                    rows = _parse_csv_output(f.read(), max_rows=300)
                for row in rows:
                    entry = {
                        "username": user,
                        "app_id": row.get("ValueName", ""),
                        "app_path": row.get("AppPath", row.get("ValueData", "")),
                        "launch_count": row.get("LaunchCount", ""),
                        "last_accessed": row.get("LastAccessedTime",
                                                   row.get("LastWriteTimestamp", "")),
                        "hive_path": ntuser_path,
                    }
                    all_entries.append(entry)
            except Exception as e:
                logger.error(f"Error parsing RecentApps CSV for {user}: {e}")
            finally:
                if os.path.exists(csv_path):
                    os.remove(csv_path)

    return json.dumps({
        "artifact_source": "recentapps",
        "case_id": case_id,
        "users_analyzed": [os.path.basename(os.path.dirname(p)) for p in ntuser_files],
        "total_entries": len(all_entries),
        "entries": all_entries,
        "parser": "RECmd",
        "status": "success" if all_entries else "no_results",
    })


@mcp.tool()
def analyze_sysmon(case_id: str, event_ids: str = "", max_events: int = 200) -> str:
    """
    Analyze Sysmon event logs from the evidence image.

    Parses the Microsoft-Windows-Sysmon/Operational EVTX log using
    EvtxECmd (Eric Zimmerman / SIFT-native).  Returns structured JSON
    with event IDs, process creation details, network connections,
    and timestamps.

    Common Sysmon Event IDs:
        1=ProcessCreate, 3=NetworkConnect, 7=ImageLoaded,
        8=CreateRemoteThread, 11=FileCreate, 13=RegistryValueSet,
        22=DNSQuery, 25=ProcessTampering

    Args:
        case_id: The case identifier.
        event_ids: Comma-separated Sysmon event IDs to filter (e.g. '1,3,11').
        max_events: Maximum number of events to return (default 200).

    Returns:
        Structured JSON with artifact_source, timestamps, and parsed entries.
    """
    evtx_path = safe_evidence_path(case_id, ARTIFACT_PATHS["sysmon"])
    if evtx_path is None:
        return json.dumps({"error": "Path traversal detected"})

    if not os.path.exists(evtx_path):
        return json.dumps({
            "error": f"Sysmon EVTX not found at {ARTIFACT_PATHS['sysmon']}",
            "artifact_source": "sysmon",
            "case_id": case_id,
        })

    csv_path = "/tmp/sysmon_output.csv"
    cmd = [
        "EvtxECmd", "-f", evtx_path,
        "--csv", "/tmp", "--csvf", "sysmon_output.csv"
    ]
    res = run_local_command(cmd, timeout=180)

    entries: List[Dict[str, Any]] = []
    filter_ids = set()
    if event_ids:
        filter_ids = {eid.strip() for eid in event_ids.split(",")}

    if os.path.exists(csv_path):
        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                rows = _parse_csv_output(f.read(), max_rows=max_events * 2)
            for row in rows:
                eid = row.get("EventId", row.get("EventID", ""))
                if filter_ids and str(eid) not in filter_ids:
                    continue
                entry = {
                    "event_id": eid,
                    "timestamp": row.get("TimeCreated", row.get("Timestamp", "")),
                    "computer": row.get("Computer", ""),
                    "channel": row.get("Channel", "Microsoft-Windows-Sysmon/Operational"),
                    "payload": row.get("PayloadData1", ""),
                    "payload2": row.get("PayloadData2", ""),
                    "payload3": row.get("PayloadData3", ""),
                    "executable_info": row.get("ExecutableInfo", ""),
                    "map_description": row.get("MapDescription", ""),
                    "user_name": row.get("UserName", ""),
                }
                entries.append(entry)
                if len(entries) >= max_events:
                    break
        except Exception as e:
            logger.error(f"Error parsing Sysmon CSV: {e}")
        finally:
            if os.path.exists(csv_path):
                os.remove(csv_path)

    return json.dumps({
        "artifact_source": "sysmon",
        "case_id": case_id,
        "artifact_path": ARTIFACT_PATHS["sysmon"],
        "event_id_filter": list(filter_ids) if filter_ids else "all",
        "total_entries": len(entries),
        "entries": entries,
        "parser": "EvtxECmd",
        "status": "success" if entries else ("parser_error" if res["status"] != "success" else "no_results"),
        "parser_stderr": res.get("stderr", "")[:300] if res["status"] != "success" else "",
    })


@mcp.tool()
def analyze_evtx(case_id: str, log_name: str = "Security", event_ids: str = "", max_events: int = 200) -> str:
    """
    Analyze Windows Event Log (EVTX) files from the evidence image.

    Parses the specified EVTX log using EvtxECmd (Eric Zimmerman / SIFT-native).
    Returns structured JSON with event IDs, timestamps, descriptions, and
    payload data.

    Common log names: Security, System, Application
    Common Security Event IDs: 4624=Logon, 4625=FailedLogon, 4688=ProcessCreate,
        4672=SpecialPrivileges, 4720=AccountCreated, 7045=ServiceInstalled

    Args:
        case_id: The case identifier.
        log_name: EVTX log name — 'Security', 'System', or 'Application'.
        event_ids: Comma-separated event IDs to filter (e.g. '4624,4625,4688').
        max_events: Maximum number of events to return (default 200).

    Returns:
        Structured JSON with artifact_source, timestamps, and parsed entries.
    """
    # Map log_name to file path
    log_map = {
        "security": ARTIFACT_PATHS["evtx_security"],
        "system": ARTIFACT_PATHS["evtx_system"],
        "application": ARTIFACT_PATHS["evtx_application"],
    }
    relative = log_map.get(log_name.lower())
    if relative is None:
        return json.dumps({
            "error": f"Unknown log_name '{log_name}'. Supported: Security, System, Application",
            "artifact_source": "evtx",
            "case_id": case_id,
        })

    evtx_path = safe_evidence_path(case_id, relative)
    if evtx_path is None:
        return json.dumps({"error": "Path traversal detected"})

    if not os.path.exists(evtx_path):
        return json.dumps({
            "error": f"{log_name}.evtx not found at {relative}",
            "artifact_source": "evtx",
            "case_id": case_id,
        })

    csv_path = f"/tmp/evtx_{log_name.lower()}_output.csv"
    cmd = [
        "EvtxECmd", "-f", evtx_path,
        "--csv", "/tmp", "--csvf", f"evtx_{log_name.lower()}_output.csv"
    ]
    res = run_local_command(cmd, timeout=180)

    entries: List[Dict[str, Any]] = []
    filter_ids = set()
    if event_ids:
        filter_ids = {eid.strip() for eid in event_ids.split(",")}

    if os.path.exists(csv_path):
        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                rows = _parse_csv_output(f.read(), max_rows=max_events * 2)
            for row in rows:
                eid = row.get("EventId", row.get("EventID", ""))
                if filter_ids and str(eid) not in filter_ids:
                    continue
                entry = {
                    "event_id": eid,
                    "timestamp": row.get("TimeCreated", row.get("Timestamp", "")),
                    "computer": row.get("Computer", ""),
                    "channel": row.get("Channel", ""),
                    "provider": row.get("Provider", ""),
                    "payload": row.get("PayloadData1", ""),
                    "payload2": row.get("PayloadData2", ""),
                    "payload3": row.get("PayloadData3", ""),
                    "map_description": row.get("MapDescription", ""),
                    "user_name": row.get("UserName", ""),
                    "executable_info": row.get("ExecutableInfo", ""),
                }
                entries.append(entry)
                if len(entries) >= max_events:
                    break
        except Exception as e:
            logger.error(f"Error parsing EVTX CSV for {log_name}: {e}")
        finally:
            if os.path.exists(csv_path):
                os.remove(csv_path)

    return json.dumps({
        "artifact_source": "evtx",
        "log_name": log_name,
        "case_id": case_id,
        "artifact_path": relative,
        "event_id_filter": list(filter_ids) if filter_ids else "all",
        "total_entries": len(entries),
        "entries": entries,
        "parser": "EvtxECmd",
        "status": "success" if entries else ("parser_error" if res["status"] != "success" else "no_results"),
        "parser_stderr": res.get("stderr", "")[:300] if res["status"] != "success" else "",
    })


@mcp.tool()
def analyze_powershell_logs(case_id: str, event_ids: str = "", search_term: str = "", max_events: int = 200) -> str:
    """
    Analyze PowerShell Operational and ScriptBlock event logs.

    Parses the Microsoft-Windows-PowerShell/Operational EVTX log using
    EvtxECmd.  Returns structured JSON with script block text, command
    invocations, and timestamps.

    Key Event IDs:
        4103=Module Logging, 4104=ScriptBlock Logging,
        4105=ScriptBlock Start, 4106=ScriptBlock Stop

    Args:
        case_id: The case identifier.
        event_ids: Comma-separated event IDs to filter (e.g. '4104').
        search_term: Optional substring to filter script block content.
        max_events: Maximum number of events to return (default 200).

    Returns:
        Structured JSON with artifact_source, timestamps, and parsed entries.
    """
    evtx_path = safe_evidence_path(case_id, ARTIFACT_PATHS["powershell_operational"])
    if evtx_path is None:
        return json.dumps({"error": "Path traversal detected"})

    if not os.path.exists(evtx_path):
        return json.dumps({
            "error": f"PowerShell EVTX not found at {ARTIFACT_PATHS['powershell_operational']}",
            "artifact_source": "powershell_logs",
            "case_id": case_id,
        })

    csv_path = "/tmp/powershell_output.csv"
    cmd = [
        "EvtxECmd", "-f", evtx_path,
        "--csv", "/tmp", "--csvf", "powershell_output.csv"
    ]
    res = run_local_command(cmd, timeout=180)

    entries: List[Dict[str, Any]] = []
    filter_ids = set()
    if event_ids:
        filter_ids = {eid.strip() for eid in event_ids.split(",")}

    if os.path.exists(csv_path):
        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                rows = _parse_csv_output(f.read(), max_rows=max_events * 2)
            for row in rows:
                eid = row.get("EventId", row.get("EventID", ""))
                if filter_ids and str(eid) not in filter_ids:
                    continue

                payload = row.get("PayloadData1", "") + " " + row.get("PayloadData2", "") + " " + row.get("PayloadData3", "")
                if search_term and search_term.lower() not in payload.lower():
                    continue

                entry = {
                    "event_id": eid,
                    "timestamp": row.get("TimeCreated", row.get("Timestamp", "")),
                    "computer": row.get("Computer", ""),
                    "channel": row.get("Channel", ""),
                    "script_block_text": row.get("PayloadData1", ""),
                    "payload2": row.get("PayloadData2", ""),
                    "payload3": row.get("PayloadData3", ""),
                    "map_description": row.get("MapDescription", ""),
                    "user_name": row.get("UserName", ""),
                    "executable_info": row.get("ExecutableInfo", ""),
                }
                entries.append(entry)
                if len(entries) >= max_events:
                    break
        except Exception as e:
            logger.error(f"Error parsing PowerShell CSV: {e}")
        finally:
            if os.path.exists(csv_path):
                os.remove(csv_path)

    return json.dumps({
        "artifact_source": "powershell_logs",
        "case_id": case_id,
        "artifact_path": ARTIFACT_PATHS["powershell_operational"],
        "event_id_filter": list(filter_ids) if filter_ids else "all",
        "search_term": search_term if search_term else None,
        "total_entries": len(entries),
        "entries": entries,
        "parser": "EvtxECmd",
        "status": "success" if entries else ("parser_error" if res["status"] != "success" else "no_results"),
        "parser_stderr": res.get("stderr", "")[:300] if res["status"] != "success" else "",
    })


@mcp.tool()
def analyze_usn_journal(case_id: str, filename_filter: str = "", reason_filter: str = "", max_entries: int = 300) -> str:
    """
    Analyze the NTFS USN (Update Sequence Number) Journal.

    Parses the $UsnJrnl:$J file using MFTECmd (Eric Zimmerman / SIFT-native)
    or falls back to fsutil-style parsing.  Returns structured JSON with
    file names, change reasons, timestamps, and parent MFT references.

    Common USN reasons: FILE_CREATE, FILE_DELETE, DATA_EXTEND, RENAME_NEW_NAME,
        SECURITY_CHANGE, CLOSE

    Args:
        case_id: The case identifier.
        filename_filter: Optional substring to filter by file name.
        reason_filter: Optional substring to filter by change reason.
        max_entries: Maximum number of entries to return (default 300).

    Returns:
        Structured JSON with artifact_source, timestamps, and parsed entries.
    """
    evidence_dir = safe_evidence_path(case_id, "")
    if evidence_dir is None:
        return json.dumps({"error": "Path traversal detected"})

    # USN Journal may be at $Extend/$UsnJrnl:$J or extracted as a file
    usn_candidates = [
        os.path.join(evidence_dir, "$Extend", "$UsnJrnl_$J"),
        os.path.join(evidence_dir, "$Extend", "$UsnJrnl"),
        os.path.join(evidence_dir, "$UsnJrnl"),
    ]
    # Also search for any pre-extracted USN files
    usn_extracted = _find_files(evidence_dir, "*UsnJrnl*")
    usn_candidates.extend(usn_extracted)

    usn_path = None
    for candidate in usn_candidates:
        if os.path.exists(candidate):
            usn_path = candidate
            break

    if usn_path is None:
        # Try MFTECmd on the $MFT file instead — it can parse USN from $MFT
        mft_path = os.path.join(evidence_dir, "$MFT")
        if not os.path.exists(mft_path):
            return json.dumps({
                "error": "USN Journal ($UsnJrnl) and $MFT not found in evidence",
                "artifact_source": "usn_journal",
                "case_id": case_id,
                "searched_paths": [p for p in usn_candidates[:3]],
            })
        usn_path = mft_path

    csv_path = "/tmp/usn_output.csv"
    cmd = [
        "MFTECmd", "-f", usn_path,
        "--csv", "/tmp", "--csvf", "usn_output.csv"
    ]
    res = run_local_command(cmd, timeout=300)

    entries: List[Dict[str, Any]] = []
    if os.path.exists(csv_path):
        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                rows = _parse_csv_output(f.read(), max_rows=max_entries * 2)
            for row in rows:
                name = row.get("FileName", row.get("Name", ""))
                reason = row.get("UpdateReasons", row.get("Reason", ""))

                if filename_filter and filename_filter.lower() not in name.lower():
                    continue
                if reason_filter and reason_filter.lower() not in reason.lower():
                    continue

                entry = {
                    "file_name": name,
                    "update_timestamp": row.get("UpdateTimestamp",
                                                 row.get("Timestamp", "")),
                    "update_reasons": reason,
                    "file_attributes": row.get("FileAttributes", ""),
                    "parent_path": row.get("ParentPath", ""),
                    "entry_number": row.get("EntryNumber", ""),
                    "sequence_number": row.get("SequenceNumber", ""),
                    "parent_entry_number": row.get("ParentEntryNumber", ""),
                    "source_info": row.get("SourceInfo", ""),
                }
                entries.append(entry)
                if len(entries) >= max_entries:
                    break
        except Exception as e:
            logger.error(f"Error parsing USN CSV: {e}")
        finally:
            if os.path.exists(csv_path):
                os.remove(csv_path)

    return json.dumps({
        "artifact_source": "usn_journal",
        "case_id": case_id,
        "usn_file": usn_path,
        "filename_filter": filename_filter if filename_filter else None,
        "reason_filter": reason_filter if reason_filter else None,
        "total_entries": len(entries),
        "entries": entries,
        "parser": "MFTECmd",
        "status": "success" if entries else ("parser_error" if res["status"] != "success" else "no_results"),
        "parser_stderr": res.get("stderr", "")[:300] if res["status"] != "success" else "",
    })


if __name__ == "__main__":
    # When executed, start the MCP server
    mcp.run()
