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

    found_prefetch = False
    if os.path.isdir(prefetch_dir):
        found_prefetch = True
    else:
        # Check other known likely locations
        likely_relative_paths = [
            "WINDOWS/Prefetch",
            "windows/Prefetch",
            "Windows/prefetch"
        ]
        for rel_path in likely_relative_paths:
            cand_path = safe_evidence_path(case_id, rel_path)
            if cand_path and os.path.isdir(cand_path):
                prefetch_dir = cand_path
                found_prefetch = True
                break

    if not found_prefetch:
        # Bounded os.walk search: max depth 4, do not follow symlinks, prune directories
        for root, dirs, files in os.walk(evidence_dir, followlinks=False):
            # Calculate current depth relative to evidence_dir
            if root == evidence_dir:
                depth = 0
            else:
                rel = os.path.relpath(root, evidence_dir)
                depth = len(rel.split(os.sep))
            
            # Prune directories we don't want to visit
            prune_names = {
                "documents and settings",
                "system volume information",
                "$recycle.bin",
                "recovery",
                "winsxs",
                "program files",
                "program files (x86)",
                "users",
                "programdata"
            }
            # Modify dirs in-place to prune them from traversal
            dirs[:] = [d for d in dirs if d.lower() not in prune_names]
            
            # Limit depth recursion
            if depth >= 4:
                dirs.clear()
            
            # Stop as soon as a directory named Prefetch is found
            for d in dirs:
                if d.lower() == "prefetch":
                    prefetch_dir = os.path.join(root, d)
                    found_prefetch = True
                    break
            if found_prefetch:
                break

    if not found_prefetch:
        # Check if Windows directory exists (case-insensitively)
        windows_exists = False
        for win_name in ["Windows", "WINDOWS", "windows"]:
            win_dir = safe_evidence_path(case_id, win_name)
            if win_dir and os.path.isdir(win_dir):
                windows_exists = True
                break

        if windows_exists:
            return json.dumps({
                "status": "no_results",
                "artifact_source": "prefetch",
                "case_id": case_id,
                "error": "Prefetch directory not found.",
                "possible_reason": "Windows XP, Prefetch disabled, Prefetch cleared, or unsupported mounted layout",
                "pivot_suggestion": "analyze_mft with filename_filter='Prefetch'"
            })
        else:
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
    evidence_dir = safe_evidence_path(case_id, "")
    if evidence_dir is None:
        return json.dumps({"error": "Path traversal detected"})

    amcache_path = safe_evidence_path(case_id, ARTIFACT_PATHS["amcache"])
    if amcache_path is None:
        return json.dumps({"error": "Path traversal detected"})

    if not os.path.exists(amcache_path):
        # Fallback: search for Amcache.hve anywhere in evidence
        amcache_candidates = glob.glob(
            os.path.join(evidence_dir, "**", "Amcache.hve"),
            recursive=True
        )
        if amcache_candidates:
            amcache_path = amcache_candidates[0]
        else:
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
def analyze_shimcache(case_id: str, executable_filter: str = "", summary_only: bool = False) -> str:
    """
    Analyze the Application Compatibility Cache (ShimCache) from the SYSTEM hive.

    Parses using AppCompatCacheParser (Eric Zimmerman / SIFT-native).
    Returns structured JSON with executable paths, last-modified times,
    and cache entry positions.

    Args:
        case_id: The case identifier.
        executable_filter: Optional substring to filter by path.
        summary_only: If True, return only a summary with top 10 suspicious entries.

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

    if summary_only and entries:
        suspicious_keywords = [
            "temp", "tmp", "appdata", "downloads", "desktop", "recycle",
            "psexec", "pwdump", "mimikatz", "cobalt", "beacon", "rat",
            "netcat", "nc.exe",
        ]
        suspicious_entries = []
        executed_count = 0
        for e in entries:
            path_lower = e.get("path", "").lower()
            executed = e.get("executed_flag", "").lower() in ("yes", "true", "1")
            if executed:
                executed_count += 1
            # Check for suspicious path keywords with executed flag
            if executed and any(kw in path_lower for kw in suspicious_keywords):
                suspicious_entries.append(e)
            # Also flag cmd.exe or powershell from non-system paths
            elif executed:
                if ("cmd.exe" in path_lower and "system32" not in path_lower) or \
                   ("powershell" in path_lower and "system32" not in path_lower):
                    suspicious_entries.append(e)

        suspicious_entries = suspicious_entries[:10]
        top_names = [os.path.basename(e.get("path", "")) for e in suspicious_entries]
        return json.dumps({
            "artifact_source": "shimcache",
            "case_id": case_id,
            "total_entries": len(entries),
            "suspicious_entries": suspicious_entries,
            "summary": f"Found {len(entries)} entries. {executed_count} show executed_flag=Yes. "
                       f"Top suspicious: {top_names}",
            "parser": "AppCompatCacheParser",
            "status": "success",
            "note": "Call with summary_only=false to get all entries"
        })

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
def analyze_sysmon(case_id: str, event_ids: str = "", max_events: int = 200, summary_only: bool = False) -> str:
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
        summary_only: If True, return only a summary with up to 50 filtered entries.

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

    if summary_only and entries:
        capped = entries[:50]
        eid_counts = {}
        for e in entries:
            eid = str(e.get("event_id", "unknown"))
            eid_counts[eid] = eid_counts.get(eid, 0) + 1
        return json.dumps({
            "artifact_source": "sysmon",
            "case_id": case_id,
            "total_entries": len(entries),
            "suspicious_entries": capped,
            "summary": f"Found {len(entries)} Sysmon events. "
                       f"Event ID distribution: {eid_counts}",
            "parser": "EvtxECmd",
            "status": "success",
            "note": "Call with summary_only=false to get all entries"
        })

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
def analyze_evtx(case_id: str, log_name: str = "Security", event_ids: str = "", max_events: int = 200, logon_type: str = "", summary_only: bool = False) -> str:
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
        logon_type: Optional logon type filter for 4624 events (e.g. '3' for network, '10' for RDP).
        summary_only: If True, return only a summary with up to 50 filtered entries.

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

                # Apply logon_type filter for 4624 events
                if logon_type and str(eid) == "4624":
                    all_payload = (entry.get("payload", "") + " " +
                                   entry.get("payload2", "") + " " +
                                   entry.get("payload3", "") + " " +
                                   entry.get("map_description", ""))
                    if (f"LogonType: {logon_type}" not in all_payload and
                        f"Logon Type:{logon_type}" not in all_payload and
                        f"Logon Type: {logon_type}" not in all_payload):
                        continue

                entries.append(entry)
                if len(entries) >= max_events:
                    break
        except Exception as e:
            logger.error(f"Error parsing EVTX CSV for {log_name}: {e}")
        finally:
            if os.path.exists(csv_path):
                os.remove(csv_path)

    if summary_only and entries:
        capped = entries[:50]
        eid_counts = {}
        for e in entries:
            eid = str(e.get("event_id", "unknown"))
            eid_counts[eid] = eid_counts.get(eid, 0) + 1
        return json.dumps({
            "artifact_source": "evtx",
            "log_name": log_name,
            "case_id": case_id,
            "total_entries": len(entries),
            "suspicious_entries": capped,
            "summary": f"Found {len(entries)} events in {log_name}. "
                       f"Event ID distribution: {eid_counts}",
            "parser": "EvtxECmd",
            "status": "success",
            "note": "Call with summary_only=false to get all entries"
        })

    return json.dumps({
        "artifact_source": "evtx",
        "log_name": log_name,
        "case_id": case_id,
        "artifact_path": relative,
        "event_id_filter": list(filter_ids) if filter_ids else "all",
        "logon_type_filter": logon_type if logon_type else None,
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
def analyze_usn_journal(case_id: str, filename_filter: str = "", reason_filter: str = "", max_entries: int = 300, summary_only: bool = False) -> str:
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
        summary_only: If True, return only a summary with up to 50 filtered entries.

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

    if summary_only and entries:
        capped = entries[:50]
        reason_counts = {}
        for e in entries:
            r = e.get("update_reasons", "unknown")
            reason_counts[r] = reason_counts.get(r, 0) + 1
        return json.dumps({
            "artifact_source": "usn_journal",
            "case_id": case_id,
            "total_entries": len(entries),
            "suspicious_entries": capped,
            "summary": f"Found {len(entries)} USN journal entries. "
                       f"Reason distribution: {reason_counts}",
            "parser": "MFTECmd",
            "status": "success",
            "note": "Call with summary_only=false to get all entries"
        })

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

# ===================================================================
# EXPANDED ANALYSIS TOOLS — 10 additional read-only DFIR tools
# ===================================================================

@mcp.tool()
def analyze_mft(case_id: str, filename_filter: str = "", max_entries: int = 300, summary_only: bool = False) -> str:
    """
    Analyze the $MFT (Master File Table) from the evidence image.

    Parses the $MFT file using MFTECmd (Eric Zimmerman / SIFT-native).
    Returns structured JSON with file metadata including entry numbers,
    file names, paths, timestamps, and size information.

    Args:
        case_id: The case identifier (e.g. 'case_001').
        filename_filter: Optional substring to filter results by file name.
        max_entries: Maximum number of entries to return (default 300).
        summary_only: If True, return only a summary with up to 50 filtered entries.

    Returns:
        Structured JSON with artifact_source, timestamps, and parsed entries.
    """
    evidence_dir = safe_evidence_path(case_id, "")
    if evidence_dir is None:
        return json.dumps({"error": "Path traversal detected"})

    mft_path = os.path.join(evidence_dir, "$MFT")
    if not os.path.exists(mft_path):
        return json.dumps({
            "error": "$MFT file not found in evidence root",
            "artifact_source": "mft",
            "case_id": case_id,
        })

    csv_path = "/tmp/mft_output.csv"
    cmd = [
        "MFTECmd", "-f", mft_path,
        "--csv", "/tmp", "--csvf", "mft_output.csv"
    ]
    res = run_local_command(cmd, timeout=300)

    entries: List[Dict[str, Any]] = []
    if os.path.exists(csv_path):
        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                rows = _parse_csv_output(f.read(), max_rows=max_entries * 2)
            for row in rows:
                name = row.get("FileName", row.get("Name", ""))
                if filename_filter and filename_filter.lower() not in name.lower():
                    continue
                entry = {
                    "entry_number": row.get("EntryNumber", ""),
                    "sequence_number": row.get("SequenceNumber", ""),
                    "file_name": name,
                    "full_path": row.get("FullPath", row.get("ParentPath", "") + "/" + name),
                    "created": row.get("Created0x10", row.get("Created", "")),
                    "modified": row.get("LastModified0x10", row.get("LastModified", "")),
                    "accessed": row.get("LastAccess0x10", row.get("LastAccess", "")),
                    "is_directory": row.get("IsDirectory", row.get("Directory", "")),
                    "size": row.get("FileSize", row.get("LogicalSize", "")),
                    "parent_path": row.get("ParentPath", ""),
                }
                entries.append(entry)
                if len(entries) >= max_entries:
                    break
        except Exception as e:
            logger.error(f"Error parsing MFT CSV: {e}")
        finally:
            if os.path.exists(csv_path):
                os.remove(csv_path)

    if summary_only and entries:
        capped = entries[:50]
        dir_count = sum(1 for e in entries if str(e.get("is_directory", "")).lower() in ("true", "1"))
        file_count = len(entries) - dir_count
        return json.dumps({
            "artifact_source": "mft",
            "case_id": case_id,
            "total_entries": len(entries),
            "suspicious_entries": capped,
            "summary": f"Found {len(entries)} MFT entries ({file_count} files, {dir_count} directories).",
            "parser": "MFTECmd",
            "status": "success",
            "note": "Call with summary_only=false to get all entries"
        })

    return json.dumps({
        "artifact_source": "mft",
        "case_id": case_id,
        "artifact_path": "$MFT",
        "total_entries": len(entries),
        "entries": entries,
        "parser": "MFTECmd",
        "status": "success" if entries else ("parser_error" if res["status"] != "success" else "no_results"),
        "parser_stderr": res.get("stderr", "")[:300] if res["status"] != "success" else "",
    })


@mcp.tool()
def analyze_registry_hive(case_id: str, hive_name: str, key_name: str = "") -> str:
    """
    Analyze a Windows registry hive from the evidence image.

    Parses the specified registry hive using RECmd (Eric Zimmerman / SIFT-native).
    Supports SYSTEM, SAM, SOFTWARE, and SECURITY hives.

    Args:
        case_id: The case identifier.
        hive_name: Registry hive name — 'SYSTEM', 'SAM', 'SOFTWARE', or 'SECURITY'.
        key_name: Optional registry key path to filter (e.g. 'ControlSet001\\Services').

    Returns:
        Structured JSON with artifact_source and parsed registry entries.
    """
    hive_map = {
        "SYSTEM": "Windows/System32/config/SYSTEM",
        "SAM": "Windows/System32/config/SAM",
        "SOFTWARE": "Windows/System32/config/SOFTWARE",
        "SECURITY": "Windows/System32/config/SECURITY",
    }

    hive_name_upper = hive_name.upper()
    relative = hive_map.get(hive_name_upper)
    if relative is None:
        return json.dumps({
            "error": f"Unknown hive_name '{hive_name}'. Supported: SYSTEM, SAM, SOFTWARE, SECURITY",
            "artifact_source": "registry",
            "case_id": case_id,
        })

    hive_path = safe_evidence_path(case_id, relative)
    if hive_path is None:
        return json.dumps({"error": "Path traversal detected"})

    if not os.path.exists(hive_path):
        return json.dumps({
            "error": f"{hive_name_upper} hive not found at {relative}",
            "artifact_source": "registry",
            "case_id": case_id,
        })

    csv_path = f"/tmp/registry_{hive_name_upper.lower()}_output.csv"
    cmd = [
        "RECmd", "-f", hive_path,
        "--csv", "/tmp", "--csvf", f"registry_{hive_name_upper.lower()}_output.csv"
    ]
    if key_name:
        cmd.extend(["--kn", key_name])

    res = run_local_command(cmd, timeout=180)

    entries: List[Dict[str, Any]] = []
    if os.path.exists(csv_path):
        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                rows = _parse_csv_output(f.read(), max_rows=500)
            for row in rows:
                entry = {
                    "key_path": row.get("KeyPath", row.get("HivePath", "")),
                    "value_name": row.get("ValueName", ""),
                    "value_data": row.get("ValueData", row.get("ValueData2", "")),
                    "value_type": row.get("ValueType", row.get("Type", "")),
                    "last_write_timestamp": row.get("LastWriteTimestamp", ""),
                    "description": row.get("Description", ""),
                }
                entries.append(entry)
        except Exception as e:
            logger.error(f"Error parsing registry CSV for {hive_name_upper}: {e}")
        finally:
            if os.path.exists(csv_path):
                os.remove(csv_path)

    return json.dumps({
        "artifact_source": "registry",
        "case_id": case_id,
        "hive_name": hive_name_upper,
        "artifact_path": relative,
        "key_filter": key_name if key_name else None,
        "total_entries": len(entries),
        "entries": entries,
        "parser": "RECmd",
        "status": "success" if entries else ("parser_error" if res["status"] != "success" else "no_results"),
        "parser_stderr": res.get("stderr", "")[:300] if res["status"] != "success" else "",
    })


@mcp.tool()
def analyze_lnk_files(case_id: str, username: str = "") -> str:
    """
    Analyze Windows shortcut (.lnk) files from the Users directory.

    Parses LNK files recursively using LECmd (Eric Zimmerman / SIFT-native).
    Returns structured JSON with target paths, timestamps, and metadata.

    Args:
        case_id: The case identifier.
        username: Optional username to target a specific user profile.

    Returns:
        Structured JSON with artifact_source and parsed LNK entries.
    """
    evidence_dir = safe_evidence_path(case_id, "")
    if evidence_dir is None:
        return json.dumps({"error": "Path traversal detected"})

    if username:
        users_dir = os.path.join(evidence_dir, "Users", username)
    else:
        users_dir = os.path.join(evidence_dir, "Users")

    if not os.path.isdir(users_dir):
        return json.dumps({
            "error": f"Users directory not found" + (f" for user '{username}'" if username else ""),
            "artifact_source": "lnk_files",
            "case_id": case_id,
        })

    csv_path = "/tmp/lnk_output.csv"
    cmd = [
        "LECmd", "-d", users_dir,
        "--csv", "/tmp", "--csvf", "lnk_output.csv"
    ]
    res = run_local_command(cmd, timeout=180)

    entries: List[Dict[str, Any]] = []
    if os.path.exists(csv_path):
        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                rows = _parse_csv_output(f.read(), max_rows=500)
            for row in rows:
                entry = {
                    "source_file": row.get("SourceFile", row.get("SourceCreated", "")),
                    "target_path": row.get("LocalPath", row.get("TargetIDAbsolutePath", "")),
                    "created": row.get("SourceCreated", row.get("Created", "")),
                    "modified": row.get("SourceModified", row.get("Modified", "")),
                    "accessed": row.get("SourceAccessed", row.get("Accessed", "")),
                    "hostname": row.get("MachineName", row.get("MachineID", "")),
                    "mac_address": row.get("MACAddress", ""),
                    "volume_label": row.get("VolumeLabel", row.get("VolumeName", "")),
                    "username": row.get("TrackerCreatedOn", ""),
                }
                entries.append(entry)
        except Exception as e:
            logger.error(f"Error parsing LNK CSV: {e}")
        finally:
            if os.path.exists(csv_path):
                os.remove(csv_path)

    return json.dumps({
        "artifact_source": "lnk_files",
        "case_id": case_id,
        "artifact_path": "Users/" + (username if username else ""),
        "total_entries": len(entries),
        "entries": entries,
        "parser": "LECmd",
        "status": "success" if entries else ("parser_error" if res["status"] != "success" else "no_results"),
        "parser_stderr": res.get("stderr", "")[:300] if res["status"] != "success" else "",
    })


@mcp.tool()
def analyze_recyclebin(case_id: str) -> str:
    """
    Analyze the Windows Recycle Bin ($Recycle.Bin) from the evidence image.

    Parses deleted file metadata using RBCmd (Eric Zimmerman / SIFT-native).
    Returns structured JSON with original file paths, deletion timestamps,
    file sizes, and user SIDs.

    Args:
        case_id: The case identifier.

    Returns:
        Structured JSON with artifact_source and parsed Recycle Bin entries.
    """
    recyclebin_path = safe_evidence_path(case_id, "$Recycle.Bin")
    if recyclebin_path is None:
        return json.dumps({"error": "Path traversal detected"})

    if not os.path.isdir(recyclebin_path):
        return json.dumps({
            "error": "$Recycle.Bin directory not found in evidence",
            "artifact_source": "recyclebin",
            "case_id": case_id,
        })

    csv_path = "/tmp/recyclebin_output.csv"
    cmd = [
        "RBCmd", "-d", recyclebin_path,
        "--csv", "/tmp", "--csvf", "recyclebin_output.csv"
    ]
    res = run_local_command(cmd, timeout=120)

    entries: List[Dict[str, Any]] = []
    if os.path.exists(csv_path):
        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                rows = _parse_csv_output(f.read(), max_rows=500)
            for row in rows:
                entry = {
                    "file_name": row.get("FileName", row.get("Name", "")),
                    "original_path": row.get("OriginalPath", row.get("FullPath", "")),
                    "deleted_on": row.get("DeletedOn", row.get("Timestamp", "")),
                    "file_size": row.get("FileSize", row.get("Size", "")),
                    "sid": row.get("SID", row.get("SecurityId", "")),
                    "username": row.get("UserName", ""),
                }
                entries.append(entry)
        except Exception as e:
            logger.error(f"Error parsing Recycle Bin CSV: {e}")
        finally:
            if os.path.exists(csv_path):
                os.remove(csv_path)

    return json.dumps({
        "artifact_source": "recyclebin",
        "case_id": case_id,
        "artifact_path": "$Recycle.Bin",
        "total_entries": len(entries),
        "entries": entries,
        "parser": "RBCmd",
        "status": "success" if entries else ("parser_error" if res["status"] != "success" else "no_results"),
        "parser_stderr": res.get("stderr", "")[:300] if res["status"] != "success" else "",
    })


@mcp.tool()
def analyze_scheduled_tasks(case_id: str, task_filter: str = "") -> str:
    """
    Analyze Windows Scheduled Tasks from the evidence image.

    Parses XML task definition files from Windows/System32/Tasks using
    Python's xml.etree.ElementTree. No external binary needed.

    Args:
        case_id: The case identifier.
        task_filter: Optional substring to filter task names.

    Returns:
        Structured JSON with artifact_source and parsed task entries.
    """
    import xml.etree.ElementTree as ET

    tasks_dir = safe_evidence_path(case_id, "Windows/System32/Tasks")
    if tasks_dir is None:
        return json.dumps({"error": "Path traversal detected"})

    if not os.path.isdir(tasks_dir):
        return json.dumps({
            "error": "Scheduled Tasks directory not found at Windows/System32/Tasks",
            "artifact_source": "scheduled_tasks",
            "case_id": case_id,
        })

    entries: List[Dict[str, Any]] = []
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

    for root_dir, dirs, files in os.walk(tasks_dir):
        for fname in files:
            fpath = os.path.join(root_dir, fname)
            try:
                tree = ET.parse(fpath)
                root = tree.getroot()

                # Handle namespace-prefixed and non-prefixed elements
                def find_text(element, tag, default=""):
                    """Find text in element with or without namespace."""
                    result = element.find(f"t:{tag}", ns)
                    if result is None:
                        result = element.find(tag)
                    return result.text if result is not None and result.text else default

                task_name = fname
                rel_path = os.path.relpath(fpath, tasks_dir)

                if task_filter and task_filter.lower() not in task_name.lower():
                    continue

                # Extract registration info
                reg_info = root.find("t:RegistrationInfo", ns) or root.find("RegistrationInfo")
                author = ""
                description = ""
                if reg_info is not None:
                    author = find_text(reg_info, "Author")
                    description = find_text(reg_info, "Description")

                # Extract actions
                command = ""
                arguments = ""
                actions = root.find("t:Actions", ns) or root.find("Actions")
                if actions is not None:
                    exec_action = actions.find("t:Exec", ns) or actions.find("Exec")
                    if exec_action is not None:
                        command = find_text(exec_action, "Command")
                        arguments = find_text(exec_action, "Arguments")

                # Extract triggers
                trigger_type = ""
                triggers = root.find("t:Triggers", ns) or root.find("Triggers")
                if triggers is not None and len(triggers) > 0:
                    trigger_type = triggers[0].tag.split("}")[-1] if "}" in triggers[0].tag else triggers[0].tag

                # Extract principal
                run_as_user = ""
                principals = root.find("t:Principals", ns) or root.find("Principals")
                if principals is not None:
                    principal = principals.find("t:Principal", ns) or principals.find("Principal")
                    if principal is not None:
                        run_as_user = find_text(principal, "UserId")

                # Extract settings
                enabled = "true"
                settings = root.find("t:Settings", ns) or root.find("Settings")
                if settings is not None:
                    enabled = find_text(settings, "Enabled", "true")

                entry = {
                    "task_name": task_name,
                    "task_path": rel_path,
                    "author": author,
                    "description": description[:200],
                    "command": command,
                    "arguments": arguments[:200],
                    "trigger_type": trigger_type,
                    "enabled": enabled,
                    "run_as_user": run_as_user,
                }
                entries.append(entry)
            except ET.ParseError:
                continue
            except Exception as e:
                logger.error(f"Error parsing task file {fpath}: {e}")
                continue

    return json.dumps({
        "artifact_source": "scheduled_tasks",
        "case_id": case_id,
        "artifact_path": "Windows/System32/Tasks",
        "total_entries": len(entries),
        "entries": entries,
        "parser": "xml.etree.ElementTree",
        "status": "success" if entries else "no_results",
    })


def _parse_rip_services(stdout: str) -> List[Dict[str, Any]]:
    entries = []
    current_ts = ""
    current_entry = {}
    
    for line in stdout.splitlines():
        line_strip = line.strip()
        if not line_strip:
            continue
            
        if line_strip.endswith(" Z") or line_strip.endswith(" UTC") or (len(line_strip.split()) >= 5 and ":" in line_strip):
            if "=" not in line_strip:
                current_ts = line_strip
                continue
        
        if "=" in line_strip:
            parts = line_strip.split("=", 1)
            key = parts[0].strip().lower()
            val = parts[1].strip()
            
            if key == "name":
                if current_entry and "service_name" in current_entry:
                    entries.append(current_entry)
                current_entry = {
                    "service_name": val,
                    "last_write_timestamp": current_ts
                }
            elif current_entry:
                if key == "display":
                    current_entry["display_name"] = val
                elif key == "imagepath":
                    current_entry["image_path"] = val
                elif key == "start":
                    current_entry["start_type"] = val
                elif key == "type":
                    current_entry["service_type"] = val
                elif key == "group":
                    current_entry["group"] = val
                    
    if current_entry and "service_name" in current_entry:
        entries.append(current_entry)
        
    return entries


def _parse_rip_sam(stdout: str) -> List[Dict[str, Any]]:
    entries = []
    current_entry = {}
    
    for line in stdout.splitlines():
        line_strip = line.strip()
        if not line_strip:
            continue
            
        if line_strip.startswith("Username"):
            if current_entry and "username" in current_entry:
                current_entry["account_flags"] = ", ".join(current_entry["account_flags"])
                entries.append(current_entry)
            
            parts = line_strip.split(":", 1)
            raw_val = parts[1].strip()
            username = raw_val
            rid = ""
            if "[" in raw_val and raw_val.endswith("]"):
                u_parts = raw_val.rsplit("[", 1)
                username = u_parts[0].strip()
                rid = u_parts[1].replace("]", "").strip()
                
            current_entry = {
                "username": username,
                "rid": rid,
                "account_flags": []
            }
            
        elif current_entry and ":" in line_strip:
            parts = line_strip.split(":", 1)
            key = parts[0].strip().lower()
            val = parts[1].strip()
            
            if key == "sid":
                current_entry["sid"] = val
            elif key == "full name":
                current_entry["full_name"] = val
            elif key == "user comment":
                current_entry["user_comment"] = val
            elif key == "account type":
                current_entry["account_type"] = val
            elif key == "account created":
                current_entry["created_on"] = val
            elif key == "last login date":
                current_entry["last_login"] = val
            elif key == "pwd reset date":
                current_entry["password_reset"] = val
            elif key == "pwd fail date":
                current_entry["password_fail"] = val
            elif key == "login count":
                current_entry["login_count"] = val
                
        elif current_entry and line_strip.startswith("-->"):
            flag = line_strip.replace("-->", "").strip()
            current_entry["account_flags"].append(flag)
            
    if current_entry and "username" in current_entry:
        current_entry["account_flags"] = ", ".join(current_entry["account_flags"])
        entries.append(current_entry)
        
    return entries


@mcp.tool()
def analyze_services(case_id: str, service_filter: str = "") -> str:
    """
    Analyze Windows services from the SYSTEM registry hive.

    Parses the ControlSet001\\Services key using RECmd (Eric Zimmerman / SIFT-native).
    Falls back to RegRipper (rip.pl) if RECmd has issues.
    Returns structured JSON with service names, image paths, start types, and descriptions.

    Args:
        case_id: The case identifier.
        service_filter: Optional substring to filter service names.

    Returns:
        Structured JSON with artifact_source and parsed service entries.
    """
    system_hive = safe_evidence_path(case_id, "Windows/System32/config/SYSTEM")
    if system_hive is None:
        return json.dumps({"error": "Path traversal detected"})

    if not os.path.exists(system_hive):
        return json.dumps({
            "error": "SYSTEM hive not found at Windows/System32/config/SYSTEM",
            "artifact_source": "services",
            "case_id": case_id,
        })

    import uuid
    reb_id = str(uuid.uuid4())
    reb_path = f"/tmp/services_{case_id}_{reb_id[:8]}.reb"
    csv_f = f"services_{case_id}_{reb_id[:8]}.csv"
    csv_path = f"/tmp/{csv_f}"

    reb_content = f"""Description: Services batch for {case_id}
Author: TriageForce
Version: 1
Id: {reb_id}
Keys:
    -
        Description: Services 001
        HiveType: SYSTEM
        Category: Execution
        KeyPath: ControlSet001\\Services
        Recursive: true
    -
        Description: Services 002
        HiveType: SYSTEM
        Category: Execution
        KeyPath: ControlSet002\\Services
        Recursive: true
    -
        Description: Services CCS
        HiveType: SYSTEM
        Category: Execution
        KeyPath: CurrentControlSet\\Services
        Recursive: true
"""

    # Write reb file
    try:
        with open(reb_path, "w", encoding="utf-8") as f:
            f.write(reb_content)
    except Exception as e:
        logger.error(f"Failed to write services reb file: {e}")

    cmd = [
        "RECmd", "-f", system_hive,
        "--bn", reb_path,
        "--csv", "/tmp", "--csvf", csv_f
    ]
    res = run_local_command(cmd, timeout=180)

    detail_csvs: List[str] = []
    if os.path.exists(csv_path):
        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    detail_file = row.get("PluginDetailFile")
                    if detail_file and os.path.exists(detail_file) and detail_file not in detail_csvs:
                        detail_csvs.append(detail_file)
        except Exception as e:
            logger.error(f"Error reading main services CSV: {e}")

    entries: List[Dict[str, Any]] = []
    parser_used = "RECmd"
    fallback_reason = ""

    for detail_file in detail_csvs:
        try:
            with open(detail_file, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    service_name = row.get("Name", row.get("ValueName", ""))
                    if not service_name:
                        continue
                    if service_filter and service_filter.lower() not in service_name.lower():
                        continue

                    entry = {
                        "service_name": service_name,
                        "display_name": row.get("DisplayName", ""),
                        "image_path": row.get("ImagePath", ""),
                        "start_type": row.get("StartMode", ""),
                        "description": row.get("Description", "")[:200] if row.get("Description") else "",
                        "service_dll": row.get("ServiceDLL", ""),
                        "last_write_timestamp": row.get("NameKeyLastWrite", row.get("LastWriteTimestamp", "")),
                    }

                    # Fallback raw row preview if none of the parsed fields are present
                    if not any(entry.get(k) for k in ["display_name", "image_path", "start_type"]):
                        entry["raw_row"] = dict(row)
                        parser_used = "RECmd (raw_rows)"

                    entries.append(entry)
        except Exception as e:
            logger.error(f"Error parsing detailed services CSV {detail_file}: {e}")

    # Cleanup RECmd generated files
    for detail_file in detail_csvs:
        try:
            if os.path.exists(detail_file):
                os.remove(detail_file)
                parent = os.path.dirname(detail_file)
                if parent != "/tmp" and os.path.isdir(parent) and not os.listdir(parent):
                    os.rmdir(parent)
        except Exception as e:
            logger.error(f"Failed to clean up detail file {detail_file}: {e}")

    try:
        if os.path.exists(csv_path):
            os.remove(csv_path)
    except Exception as e:
        logger.error(f"Failed to clean up main CSV {csv_path}: {e}")

    try:
        if os.path.exists(reb_path):
            os.remove(reb_path)
    except Exception as e:
        logger.error(f"Failed to clean up reb file {reb_path}: {e}")

    # Fallback to RegRipper if no entries parsed or RECmd failed
    if not entries:
        logger.info("RECmd returned no results or failed. Falling back to RegRipper...")
        rip_cmd = ["rip.pl", "-r", system_hive, "-p", "services"]
        rip_res = run_local_command(rip_cmd, timeout=60)
        if rip_res["status"] == "success" and rip_res["stdout"]:
            try:
                entries = _parse_rip_services(rip_res["stdout"])
                if service_filter:
                    entries = [e for e in entries if service_filter.lower() in e.get("service_name", "").lower()]
                if entries:
                    parser_used = "RegRipper"
                    fallback_reason = "RECmd returned no results; fell back to RegRipper rip.pl services plugin"
            except Exception as parse_err:
                logger.error(f"Failed to parse rip.pl services output: {parse_err}")
                fallback_reason = f"RECmd returned no results. Failed to parse rip.pl output: {parse_err}"
        else:
            fallback_reason = f"RECmd returned no results. RegRipper rip.pl failed: {rip_res.get('stderr', '')[:200]}"

    status = "success" if entries else ("parser_error" if fallback_reason and "failed" in fallback_reason.lower() else "no_results")

    return json.dumps({
        "artifact_source": "services",
        "case_id": case_id,
        "artifact_path": "Windows/System32/config/SYSTEM",
        "key_path": "ControlSet001\\Services",
        "total_entries": len(entries),
        "entries": entries,
        "parser": parser_used,
        "status": status,
        "fallback_reason": fallback_reason if fallback_reason else None,
        "parser_stderr": res.get("stderr", "")[:300] if res["status"] != "success" else "",
    })


@mcp.tool()
def analyze_sam_users(case_id: str) -> str:
    """
    Analyze local user accounts from the SAM registry hive.

    Parses the SAM\\Domains\\Account\\Users key using RECmd (Eric Zimmerman / SIFT-native).
    Falls back to RegRipper (rip.pl) if RECmd has issues.
    Returns structured JSON with usernames, RIDs, login information, and account flags.

    Args:
        case_id: The case identifier.

    Returns:
        Structured JSON with artifact_source and parsed user account entries.
    """
    sam_hive = safe_evidence_path(case_id, "Windows/System32/config/SAM")
    if sam_hive is None:
        return json.dumps({"error": "Path traversal detected"})

    if not os.path.exists(sam_hive):
        return json.dumps({
            "error": "SAM hive not found at Windows/System32/config/SAM",
            "artifact_source": "sam_users",
            "case_id": case_id,
        })

    import uuid
    reb_id = str(uuid.uuid4())
    reb_path = f"/tmp/sam_{case_id}_{reb_id[:8]}.reb"
    csv_f = f"sam_{case_id}_{reb_id[:8]}.csv"
    csv_path = f"/tmp/{csv_f}"

    reb_content = f"""Description: SAM Users batch for {case_id}
Author: TriageForce
Version: 1
Id: {reb_id}
Keys:
    -
        Description: SAM Users
        HiveType: SAM
        Category: Users
        KeyPath: SAM\\Domains\\Account\\Users
        Recursive: true
"""

    # Write reb file
    try:
        with open(reb_path, "w", encoding="utf-8") as f:
            f.write(reb_content)
    except Exception as e:
        logger.error(f"Failed to write SAM reb file: {e}")

    cmd = [
        "RECmd", "-f", sam_hive,
        "--bn", reb_path,
        "--csv", "/tmp", "--csvf", csv_f
    ]
    res = run_local_command(cmd, timeout=120)

    detail_csvs: List[str] = []
    if os.path.exists(csv_path):
        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    detail_file = row.get("PluginDetailFile")
                    if detail_file and os.path.exists(detail_file) and detail_file not in detail_csvs:
                        detail_csvs.append(detail_file)
        except Exception as e:
            logger.error(f"Error reading main SAM CSV: {e}")

    entries: List[Dict[str, Any]] = []
    parser_used = "RECmd"
    fallback_reason = ""

    for detail_file in detail_csvs:
        try:
            with open(detail_file, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    username = row.get("UserName", row.get("ValueData", ""))
                    if not username:
                        continue

                    entry = {
                        "username": username,
                        "rid": row.get("UserId", row.get("ValueName", "")),
                        "last_login": row.get("LastLoginTime", row.get("LastWriteTimestamp", "")),
                        "created_on": row.get("CreatedOn", ""),
                        "groups": row.get("Groups", ""),
                        "account_disabled": row.get("AccountDisabled", ""),
                        "comment": row.get("Comment", ""),
                        "user_comment": row.get("UserComment", ""),
                    }

                    if not any(entry.get(k) for k in ["rid", "last_login", "created_on"]):
                        entry["raw_row"] = dict(row)
                        parser_used = "RECmd (raw_rows)"

                    entries.append(entry)
        except Exception as e:
            logger.error(f"Error parsing detailed SAM CSV {detail_file}: {e}")

    # Cleanup RECmd generated files
    for detail_file in detail_csvs:
        try:
            if os.path.exists(detail_file):
                os.remove(detail_file)
                parent = os.path.dirname(detail_file)
                if parent != "/tmp" and os.path.isdir(parent) and not os.listdir(parent):
                    os.rmdir(parent)
        except Exception as e:
            logger.error(f"Failed to clean up detail file {detail_file}: {e}")

    try:
        if os.path.exists(csv_path):
            os.remove(csv_path)
    except Exception as e:
        logger.error(f"Failed to clean up main CSV {csv_path}: {e}")

    try:
        if os.path.exists(reb_path):
            os.remove(reb_path)
    except Exception as e:
        logger.error(f"Failed to clean up reb file {reb_path}: {e}")

    # Fallback to RegRipper if no entries parsed or RECmd failed
    if not entries:
        logger.info("RECmd returned no results or failed. Falling back to RegRipper...")
        rip_cmd = ["rip.pl", "-r", sam_hive, "-p", "samparse"]
        rip_res = run_local_command(rip_cmd, timeout=60)
        if rip_res["status"] == "success" and rip_res["stdout"]:
            try:
                entries = _parse_rip_sam(rip_res["stdout"])
                if entries:
                    parser_used = "RegRipper"
                    fallback_reason = "RECmd returned no results; fell back to RegRipper rip.pl samparse plugin"
            except Exception as parse_err:
                logger.error(f"Failed to parse rip.pl samparse output: {parse_err}")
                fallback_reason = f"RECmd returned no results. Failed to parse rip.pl output: {parse_err}"
        else:
            fallback_reason = f"RECmd returned no results. RegRipper rip.pl failed: {rip_res.get('stderr', '')[:200]}"

    status = "success" if entries else ("parser_error" if fallback_reason and "failed" in fallback_reason.lower() else "no_results")

    return json.dumps({
        "artifact_source": "sam_users",
        "case_id": case_id,
        "artifact_path": "Windows/System32/config/SAM",
        "key_path": "SAM\\Domains\\Account\\Users",
        "total_entries": len(entries),
        "entries": entries,
        "parser": parser_used,
        "status": status,
        "fallback_reason": fallback_reason if fallback_reason else None,
        "parser_stderr": res.get("stderr", "")[:300] if res["status"] != "success" else "",
    })


@mcp.tool()
def analyze_network_connections(case_id: str, pcap_name: str = "", filter_type: str = "connections") -> str:
    """
    Analyze network connections from PCAP files in the evidence image.

    Runs tshark with specific filters on PCAP files. Supports connection
    summaries, DNS queries, and HTTP requests.

    Args:
        case_id: The case identifier.
        pcap_name: Optional PCAP filename. If empty, searches evidence for pcap files.
        filter_type: Analysis type — 'connections', 'dns', or 'http' (default 'connections').

    Returns:
        Structured JSON with artifact_source and parsed network entries.
    """
    evidence_dir = safe_evidence_path(case_id, "")
    if evidence_dir is None:
        return json.dumps({"error": "Path traversal detected"})

    # Find PCAP file
    pcap_path = None
    if pcap_name:
        pcap_path = safe_evidence_path(case_id, pcap_name)
        if pcap_path is None:
            return json.dumps({"error": "Path traversal detected"})
        if not os.path.exists(pcap_path):
            return json.dumps({
                "error": f"PCAP file not found: {pcap_name}",
                "artifact_source": "network_connections",
                "case_id": case_id,
            })
    else:
        # Search for pcap files
        pcap_patterns = ["*.pcap", "*.pcapng", "*.cap"]
        for pattern in pcap_patterns:
            found = _find_files(evidence_dir, pattern)
            if found:
                pcap_path = found[0]
                break
        if pcap_path is None:
            return json.dumps({
                "error": "No PCAP files found in evidence directory",
                "artifact_source": "network_connections",
                "case_id": case_id,
            })

    # Validate filter_type
    if filter_type not in ("connections", "dns", "http"):
        filter_type = "connections"

    # Build command based on filter type
    if filter_type == "connections":
        cmd = ["tshark", "-r", pcap_path, "-q", "-z", "conv,tcp"]
    elif filter_type == "dns":
        cmd = ["tshark", "-r", pcap_path, "-Y", "dns", "-T", "fields",
               "-e", "frame.time", "-e", "dns.qry.name", "-e", "dns.resp.addr"]
    elif filter_type == "http":
        cmd = ["tshark", "-r", pcap_path, "-Y", "http.request", "-T", "fields",
               "-e", "frame.time", "-e", "http.host", "-e", "http.request.uri"]

    res = run_local_command(cmd, timeout=120)

    entries: List[Dict[str, Any]] = []
    if res["status"] == "success" and res["stdout"].strip():
        lines = res["stdout"].strip().split("\n")
        for line in lines[:500]:
            line = line.strip()
            if not line or line.startswith("=") or line.startswith("-") or line.startswith("Filter"):
                continue
            parts = line.split("\t") if "\t" in line else line.split()
            if filter_type == "connections":
                entry = {
                    "timestamp": "",
                    "source": parts[0] if len(parts) > 0 else "",
                    "destination": parts[2] if len(parts) > 2 else "",
                    "protocol": "TCP",
                    "info": line[:200],
                }
            elif filter_type == "dns":
                entry = {
                    "timestamp": parts[0] if len(parts) > 0 else "",
                    "source": "",
                    "destination": parts[2] if len(parts) > 2 else "",
                    "protocol": "DNS",
                    "info": parts[1] if len(parts) > 1 else "",
                }
            elif filter_type == "http":
                entry = {
                    "timestamp": parts[0] if len(parts) > 0 else "",
                    "source": parts[1] if len(parts) > 1 else "",
                    "destination": "",
                    "protocol": "HTTP",
                    "info": parts[2] if len(parts) > 2 else "",
                }
            entries.append(entry)

    return json.dumps({
        "artifact_source": "network_connections",
        "case_id": case_id,
        "pcap_file": pcap_path,
        "filter_type": filter_type,
        "total_entries": len(entries),
        "entries": entries,
        "parser": "tshark",
        "status": "success" if entries else ("parser_error" if res["status"] != "success" else "no_results"),
        "parser_stderr": res.get("stderr", "")[:300] if res["status"] != "success" else "",
    })


@mcp.tool()
def analyze_browser_history(case_id: str, username: str = "", browser: str = "") -> str:
    """
    Analyze web browser history from the evidence image.

    Parses SQLite browser databases from Users directory using Python's
    sqlite3 module. No external binary needed. Supports Chrome, Firefox, and IE.

    Args:
        case_id: The case identifier.
        username: Optional username to target a specific user profile.
        browser: Optional browser filter — 'chrome', 'firefox', or 'ie'. Empty for all.

    Returns:
        Structured JSON with artifact_source and parsed browser history entries.
    """
    import sqlite3

    evidence_dir = safe_evidence_path(case_id, "")
    if evidence_dir is None:
        return json.dumps({"error": "Path traversal detected"})

    users_dir = os.path.join(evidence_dir, "Users")
    if not os.path.isdir(users_dir):
        return json.dumps({
            "error": "Users directory not found in evidence",
            "artifact_source": "browser_history",
            "case_id": case_id,
        })

    entries: List[Dict[str, Any]] = []
    users_to_check = []

    if username:
        user_path = os.path.join(users_dir, username)
        if os.path.isdir(user_path):
            users_to_check.append((username, user_path))
    else:
        for entry in os.scandir(users_dir):
            if entry.is_dir():
                users_to_check.append((entry.name, entry.path))

    for user, user_path in users_to_check:
        # Chrome
        if not browser or browser.lower() == "chrome":
            chrome_path = os.path.join(user_path, "AppData", "Local", "Google",
                                       "Chrome", "User Data", "Default", "History")
            if os.path.exists(chrome_path):
                try:
                    conn = sqlite3.connect(f"file:{chrome_path}?mode=ro", uri=True)
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT url, title, visit_count, last_visit_time "
                        "FROM urls ORDER BY last_visit_time DESC LIMIT 200"
                    )
                    for row in cursor.fetchall():
                        entries.append({
                            "url": row[0] or "",
                            "title": row[1] or "",
                            "visit_time": str(row[3]) if row[3] else "",
                            "visit_count": str(row[2]) if row[2] else "",
                            "browser": "chrome",
                            "username": user,
                        })
                    conn.close()
                except Exception as e:
                    logger.error(f"Error reading Chrome history for {user}: {e}")

        # Firefox
        if not browser or browser.lower() == "firefox":
            firefox_dir = os.path.join(user_path, "AppData", "Roaming",
                                       "Mozilla", "Firefox", "Profiles")
            if os.path.isdir(firefox_dir):
                for profile in os.scandir(firefox_dir):
                    if profile.is_dir():
                        places_path = os.path.join(profile.path, "places.sqlite")
                        if os.path.exists(places_path):
                            try:
                                conn = sqlite3.connect(f"file:{places_path}?mode=ro", uri=True)
                                cursor = conn.cursor()
                                cursor.execute(
                                    "SELECT url, title, visit_count, last_visit_date "
                                    "FROM moz_places ORDER BY last_visit_date DESC LIMIT 200"
                                )
                                for row in cursor.fetchall():
                                    entries.append({
                                        "url": row[0] or "",
                                        "title": row[1] or "",
                                        "visit_time": str(row[3]) if row[3] else "",
                                        "visit_count": str(row[2]) if row[2] else "",
                                        "browser": "firefox",
                                        "username": user,
                                    })
                                conn.close()
                            except Exception as e:
                                logger.error(f"Error reading Firefox history for {user}: {e}")

        # IE (index.dat is binary, but we can check for WebCacheV01.dat)
        if not browser or browser.lower() == "ie":
            ie_path = os.path.join(user_path, "AppData", "Local", "Microsoft",
                                   "Windows", "WebCache", "WebCacheV01.dat")
            if os.path.exists(ie_path):
                entries.append({
                    "url": "(IE WebCache database found — binary format requires ESEDatabaseView)",
                    "title": "",
                    "visit_time": "",
                    "visit_count": "",
                    "browser": "ie",
                    "username": user,
                })

    return json.dumps({
        "artifact_source": "browser_history",
        "case_id": case_id,
        "artifact_path": "Users/*/AppData",
        "browser_filter": browser if browser else "all",
        "total_entries": len(entries),
        "entries": entries,
        "parser": "sqlite3",
        "status": "success" if entries else "no_results",
    })


@mcp.tool()
def analyze_autoruns(case_id: str) -> str:
    """
    Analyze all autorun/persistence locations from the evidence image.

    Combines registry Run keys (from SOFTWARE and NTUSER.DAT hives),
    scheduled tasks (from Windows/System32/Tasks), services (from SYSTEM hive),
    and startup folder files. Uses RECmd for registry and filesystem scan
    for startup folders.

    Args:
        case_id: The case identifier.

    Returns:
        Structured JSON with artifact_source and parsed autorun entries.
    """
    evidence_dir = safe_evidence_path(case_id, "")
    if evidence_dir is None:
        return json.dumps({"error": "Path traversal detected"})

    entries: List[Dict[str, Any]] = []

    # 1. Registry Run keys from SOFTWARE hive
    software_hive = safe_evidence_path(case_id, "Windows/System32/config/SOFTWARE")
    if software_hive and os.path.exists(software_hive):
        run_keys = [
            "Microsoft\\Windows\\CurrentVersion\\Run",
            "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ]
        for key_path in run_keys:
            csv_path = f"/tmp/autoruns_software_{key_path.replace(chr(92), '_')}.csv"
            csv_name = f"autoruns_software_{key_path.replace(chr(92), '_')}.csv"
            cmd = [
                "RECmd", "-f", software_hive,
                "--kn", key_path,
                "--csv", "/tmp", "--csvf", csv_name
            ]
            res = run_local_command(cmd, timeout=60)
            if os.path.exists(csv_path):
                try:
                    with open(csv_path, "r", encoding="utf-8-sig") as f:
                        rows = _parse_csv_output(f.read(), max_rows=100)
                    for row in rows:
                        entries.append({
                            "autorun_type": "registry_run_key",
                            "name": row.get("ValueName", ""),
                            "command": row.get("ValueData", ""),
                            "location": f"SOFTWARE\\{key_path}",
                            "username": "SYSTEM",
                            "enabled": "true",
                        })
                except Exception as e:
                    logger.error(f"Error parsing autorun registry CSV: {e}")
                finally:
                    if os.path.exists(csv_path):
                        os.remove(csv_path)

    # 2. NTUSER.DAT Run keys per user
    users_dir = os.path.join(evidence_dir, "Users")
    if os.path.isdir(users_dir):
        for user_entry in os.scandir(users_dir):
            if user_entry.is_dir():
                ntuser = os.path.join(user_entry.path, "NTUSER.DAT")
                if os.path.exists(ntuser):
                    csv_path = f"/tmp/autoruns_ntuser_{user_entry.name}.csv"
                    cmd = [
                        "RECmd", "-f", ntuser,
                        "--kn", "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "--csv", "/tmp", "--csvf", f"autoruns_ntuser_{user_entry.name}.csv"
                    ]
                    res = run_local_command(cmd, timeout=60)
                    if os.path.exists(csv_path):
                        try:
                            with open(csv_path, "r", encoding="utf-8-sig") as f:
                                rows = _parse_csv_output(f.read(), max_rows=100)
                            for row in rows:
                                entries.append({
                                    "autorun_type": "registry_run_key",
                                    "name": row.get("ValueName", ""),
                                    "command": row.get("ValueData", ""),
                                    "location": f"NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                                    "username": user_entry.name,
                                    "enabled": "true",
                                })
                        except Exception as e:
                            logger.error(f"Error parsing NTUSER autorun CSV: {e}")
                        finally:
                            if os.path.exists(csv_path):
                                os.remove(csv_path)

    # 3. Scheduled tasks
    tasks_dir = safe_evidence_path(case_id, "Windows/System32/Tasks")
    if tasks_dir and os.path.isdir(tasks_dir):
        import xml.etree.ElementTree as ET
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        for root_dir, dirs, files in os.walk(tasks_dir):
            for fname in files:
                fpath = os.path.join(root_dir, fname)
                try:
                    tree = ET.parse(fpath)
                    root = tree.getroot()
                    actions = root.find("t:Actions", ns) or root.find("Actions")
                    command = ""
                    if actions is not None:
                        exec_action = actions.find("t:Exec", ns) or actions.find("Exec")
                        if exec_action is not None:
                            cmd_elem = exec_action.find("t:Command", ns) or exec_action.find("Command")
                            command = cmd_elem.text if cmd_elem is not None and cmd_elem.text else ""
                    entries.append({
                        "autorun_type": "scheduled_task",
                        "name": fname,
                        "command": command,
                        "location": os.path.relpath(fpath, tasks_dir),
                        "username": "",
                        "enabled": "true",
                    })
                except Exception:
                    continue

    # 4. Services from SYSTEM hive
    system_hive = safe_evidence_path(case_id, "Windows/System32/config/SYSTEM")
    if system_hive and os.path.exists(system_hive):
        csv_path = "/tmp/autoruns_services.csv"
        cmd = [
            "RECmd", "-f", system_hive,
            "--kn", "ControlSet001\\Services",
            "--csv", "/tmp", "--csvf", "autoruns_services.csv"
        ]
        res = run_local_command(cmd, timeout=120)
        if os.path.exists(csv_path):
            try:
                with open(csv_path, "r", encoding="utf-8-sig") as f:
                    rows = _parse_csv_output(f.read(), max_rows=200)
                for row in rows:
                    if row.get("ValueName", "") == "ImagePath":
                        entries.append({
                            "autorun_type": "service",
                            "name": row.get("KeyPath", "").split("\\")[-1],
                            "command": row.get("ValueData", ""),
                            "location": row.get("KeyPath", ""),
                            "username": "",
                            "enabled": "true",
                        })
            except Exception as e:
                logger.error(f"Error parsing services autorun CSV: {e}")
            finally:
                if os.path.exists(csv_path):
                    os.remove(csv_path)

    # 5. Startup folders
    if os.path.isdir(users_dir):
        for user_entry in os.scandir(users_dir):
            if user_entry.is_dir():
                startup_path = os.path.join(
                    user_entry.path, "AppData", "Roaming", "Microsoft",
                    "Windows", "Start Menu", "Programs", "Startup"
                )
                if os.path.isdir(startup_path):
                    for item in os.scandir(startup_path):
                        if item.is_file():
                            entries.append({
                                "autorun_type": "startup_folder",
                                "name": item.name,
                                "command": item.path,
                                "location": startup_path,
                                "username": user_entry.name,
                                "enabled": "true",
                            })

    return json.dumps({
        "artifact_source": "autoruns",
        "case_id": case_id,
        "artifact_path": "multiple_sources",
        "total_entries": len(entries),
        "entries": entries,
        "parser": "RECmd+xml.etree+filesystem",
        "status": "success" if entries else "no_results",
    })


if __name__ == "__main__":
    # When executed, start the MCP server
    mcp.run()
