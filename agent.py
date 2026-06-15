#!/usr/bin/env python3
"""
triageforce/agent.py
--------------------
Autonomous forensic triage agent using the Google Gemini SDK + MCP Python SDK.

Connects to a remote SIFT MCP server over a passwordless SSH stdio tunnel,
runs a capped agentic loop (--max-iterations 25), performs evidence correlation
with confidence scoring and self-correction, and writes a structured audit log
to agent_execution.jsonl.

Features:
    - Evidence Correlation: Structured evidence objects with corroboration tracking
    - Confidence Scoring: Multi-source scoring with contradiction penalties
    - Self-Correction: Verification loop that challenges findings
    - DFIR Validation: Knowledge-driven rules for forensic best practices
    - Full Traceability: Every action logged with hypothesis and confidence tracking

Usage:
    python agent.py --task "List all files in /cases/case_001/evidence"
    python agent.py --task "Hash verify the E01 image" --max-iterations 10
    python agent.py --task "Run triage on mounted image" --dry-run
    python agent.py --test-connection                    # handshake only, no agent loop

Dependencies:
    pip install google-genai mcp python-dotenv

Remote MCP server is reached via passwordless SSH stdio transport:
    Host: sansforensics@192.168.255.128
    Server script: ~/triageforce/mcp_server.py  (adjust as needed)
"""

import argparse
import json
import os
import re
import sys
import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from google import genai
from google.genai import types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Load .env file (if present) before reading environment variables
load_dotenv()

# ---------------------------------------------------------------------------
# Configuration -- adjust these to match your SIFT deployment
# ---------------------------------------------------------------------------

REMOTE_HOST = "sansforensics@192.168.255.128"
REMOTE_MCP_SERVER_CMD = "sudo"
REMOTE_MCP_SERVER_ARGS = [
    "/opt/triageforce/venv/bin/python",
    "/opt/triageforce/server.py"
]

# SSH flags: BatchMode=yes ensures we fail fast if keys aren't configured
SSH_FLAGS = [
    "ssh",
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=10",
    REMOTE_HOST,
    REMOTE_MCP_SERVER_CMD,
] + REMOTE_MCP_SERVER_ARGS

GEMINI_MODEL = "gemini-2.5-flash"

AUDIT_LOG_PATH = Path("agent_execution.jsonl")

DEFAULT_MAX_ITERATIONS = 12

MAX_VERIFICATION_ITERATIONS = 3

# ---------------------------------------------------------------------------
# Investigation System Prompt -- Senior Analyst Methodology
# ---------------------------------------------------------------------------

INVESTIGATION_SYSTEM_PROMPT = (
    "You are a senior forensic triage analyst operating on a SANS SIFT workstation. "
    "The evidence image is mounted READ-ONLY at /cases/case_001/evidence. "
    "You MUST NOT invoke any tool that writes to, modifies, or deletes evidence files.\n\n"

    "INVESTIGATION PLAN:\n"
    "Before executing tools to investigate a new hypothesis or branch, you MUST formulate and emit a structured investigation plan block:\n"
    "```investigation_plan\n"
    '{"hypothesis": "clear statement of the hypothesis being tested", '
    '"required_artifacts": ["list", "of", "artifacts", "needed"], '
    '"tool_selection": "rationale for selecting specific tools", '
    '"expected_evidence": "what evidence would support/refute the hypothesis"}\n'
    "```\n"
    "You must state *why* each tool is being selected in your text before calling it.\n\n"

    "INVESTIGATION METHODOLOGY:\n"
    "Follow this workflow for every finding:\n"
    "  1. OBSERVATION -- What did the tool output show?\n"
    "  2. HYPOTHESIS -- What does this evidence suggest?\n"
    "  3. EVIDENCE COLLECTION -- What additional artifacts should be checked?\n"
    "  4. VERIFICATION -- Does the additional evidence support or contradict?\n"
    "  5. CONCLUSION -- What is the final assessment with confidence level?\n\n"

    "EVIDENCE CORRELATION RULES:\n"
    "- Never treat a single artifact as high-confidence evidence.\n"
    "- Prefer multiple independent evidence sources for any claim.\n"
    "- Treat contradictions as investigation signals, not failures.\n"
    "- Require corroboration for execution claims (e.g., Prefetch + Amcache).\n"
    "- Require corroboration for lateral movement claims (network + host evidence).\n"
    "- Require corroboration for persistence claims (registry + filesystem).\n"
    "- When citing evidence, be precise: include file paths, hash values, and timestamps.\n\n"

    "ARTIFACT PRIORITIZATION ORDER:\n"
    "You MUST run lightweight, targeted artifact tools BEFORE broad filesystem scans.\n"
    "Follow this priority order for every investigation:\n"
    "  Priority 1 (run FIRST):\n"
    "    - analyze_amcache (execution evidence with SHA1 hashes)\n"
    "    - analyze_shimcache (execution evidence with timestamps)\n"
    "    - analyze_evtx with event_ids='7045' log_name='System' (service installations)\n"
    "    - analyze_evtx with event_ids='4624,4672,4688' log_name='Security' (logons, privileges, process creation)\n"
    "    - analyze_sysmon (process creation, network, file events)\n"
    "    - analyze_powershell_logs (script block logging)\n"
    "    - analyze_services (persistence via services)\n"
    "    - analyze_scheduled_tasks (persistence via tasks)\n"
    "    - analyze_autoruns (all persistence locations)\n"
    "  Priority 2 (run SECOND, only after Priority 1):\n"
    "    - analyze_prefetch (execution with run counts)\n"
    "    - analyze_userassist / analyze_recentapps\n"
    "    - analyze_lnk_files / analyze_recyclebin\n"
    "    - analyze_sam_users / analyze_browser_history\n"
    "  Priority 3 (run LAST, only with specific filters):\n"
    "    - analyze_mft -- ALWAYS use filename_filter (e.g. filename_filter='Sysmon64.exe')\n"
    "    - analyze_usn_journal -- ALWAYS use filename_filter or reason_filter\n"
    "    - analyze_registry_hive -- ALWAYS use key_name (e.g. key_name='ControlSet001\\\\Services')\n"
    "  NEVER run analyze_mft, analyze_usn_journal, or analyze_registry_hive without a filter.\n"
    "  Broad unfiltered scans are expensive, will time out, and waste iterations.\n\n"

    "TIMEOUT AND BROAD SCAN SAFETY:\n"
    "The following tools have hard execution timeouts and WILL return status='timeout' if they exceed the limit:\n"
    "  - analyze_mft without filename_filter: 60-second timeout\n"
    "  - analyze_usn_journal without filename_filter: 60-second timeout\n"
    "  - analyze_registry_hive without key_name: 60-second timeout\n"
    "When you receive a status='timeout' response:\n"
    "  1. Do NOT retry the same broad query.\n"
    "  2. Read the pivot_suggestion field in the response and follow it.\n"
    "  3. Rerun the tool with a specific filter, or switch to a Priority 1 artifact.\n"
    "  4. Document the timeout in your investigation notes.\n\n"

    "FORENSIC PIVOT RULES:\n"
    "When a tool returns an error or no results, do NOT skip the "
    "artifact class. Instead:\n"
    "  1. If analyze_prefetch fails: run analyze_mft with "
    "filename_filter='Prefetch' to locate the directory in the MFT\n"
    "  2. If analyze_amcache fails: run analyze_shimcache as the "
    "primary execution artifact instead\n"
    "  3. If analyze_evtx fails: run analyze_sysmon as the "
    "alternative event source\n"
    "  4. If analyze_sysmon fails: run analyze_powershell_logs\n"
    "  5. Always document the pivot: which tool failed, why, "
    "and what alternative was used\n"
    "A senior analyst never abandons an artifact class because "
    "one tool failed. They find another path to the same evidence.\n\n"

    "PSEXEC DETECTION PROTOCOL:\n"
    "When PSEXESVC.exe or PsExec.exe appears in any artifact:\n"
    "  1. Immediately run analyze_evtx with log_name='System' "
    "and event_ids='7045' to check for service installation\n"
    "  2. Run analyze_evtx with log_name='Security' and "
    "event_ids='4624' filtering for LogonType 3 or 10 around "
    "the PsExec timestamp to identify the remote source\n"
    "  3. Run analyze_services to verify PSEXESVC is/was "
    "registered as a service\n"
    "  4. Run analyze_sysmon with event_ids='1,3' to find "
    "the process creation and network connection\n"
    "This is mandatory when PsExec is detected. Do not proceed "
    "to other findings until this chain is complete.\n\n"

    "CREDENTIAL DUMPING PROTOCOL:\n"
    "When PWDumpX.exe, mimikatz, or similar credential dumpers "
    "appear in any artifact:\n"
    "  1. Run analyze_evtx with log_name='Security' and "
    "event_ids='4624,4625,4648' to find logons using "
    "dumped credentials\n"
    "  2. Run analyze_sam_users to enumerate what accounts "
    "existed and could have been dumped\n"
    "  3. Run analyze_sysmon with event_ids='8' to check for "
    "process injection into LSASS\n"
    "This is mandatory when credential dumpers are detected.\n\n"

    "PERSISTENCE PIVOT PROTOCOL:\n"
    "When Schtasks.exe, Task Scheduler artifacts, Registry Run keys, Reg.exe, services, startup folders, or autorun indicators appear in any artifact:\n"
    "  1. Run analyze_scheduled_tasks to enumerate scheduled tasks and commands.\n"
    "  2. Run analyze_autoruns to correlate Run keys, services, tasks, and startup folders.\n"
    "  3. If Reg.exe or registry modification appears, run analyze_registry_hive against SOFTWARE and SYSTEM for Run keys, Services, and TaskCache-related keys where available.\n"
    "  4. Correlate persistence artifacts with ShimCache, Sysmon Event ID 1, Security 4688, and MFT/USN timestamps before making a high-confidence persistence finding.\n"
    "  5. Map confirmed scheduled task persistence to T1053.005 and registry persistence/modification to T1112 only when supported by artifact details.\n"
    "This protocol is mandatory when scheduled task or registry persistence indicators are detected.\n\n"

    "ADMINISTRATOR LOGON VERIFICATION PROTOCOL:\n"
    "When Administrator, BASE-FTP\\Administrator, or another privileged account appears in Security 4624 logons:\n"
    "  1. Run analyze_evtx with log_name='Security' and event_ids='4672' around the same time window to check for special privileges assigned.\n"
    "  2. Run analyze_evtx with log_name='Security' and event_ids='4648' to check for explicit credential use.\n"
    "  3. If remote access is suspected, run analyze_evtx with log_name='Security', event_ids='4624', and logon_type='3'.\n"
    "  4. If RDP or remote interactive access is suspected, run analyze_evtx with log_name='Security', event_ids='4624', and logon_type='10'.\n"
    "  5. Correlate privileged logons with process creation, services, scheduled tasks, autoruns, and network connections before claiming lateral movement.\n"
    "  6. Map confirmed valid account abuse to T1078 only when privilege or remote-use evidence is present.\n"
    "This protocol is mandatory when privileged account logons are detected.\n\n"

    "SYSMON64 AND POWERSHELL DELIVERY PROTOCOL:\n"
    "When Sysmon64.exe appears from an unusual path such as C:\\ProgramData\\sysmon\\ or a user-writable directory:\n"
    "  1. Run analyze_sysmon with event_ids='1' to find process creation for Sysmon64.exe and parent process context.\n"
    "  2. Run analyze_powershell_logs with search_term='sysmon' and event_ids='4103,4104' to identify PowerShell download or execution commands.\n"
    "  3. Run analyze_evtx with log_name='Security' and event_ids='4688' to look for process creation evidence if available.\n"
    "  4. Run analyze_mft or analyze_usn_journal with filename_filter='Sysmon64.exe' to identify file creation or modification timing.\n"
    "  5. Treat Sysmon as dual-use: do not call it malicious unless the path, parent process, command line, download source, or timing supports adversary use.\n"
    "  6. Map PowerShell delivery to T1059.001 only when command/script evidence exists.\n"
    "This protocol is mandatory when Sysmon64.exe appears outside standard defender deployment context.\n\n"

    "SINGLE-ARTIFACT CORROBORATION PROTOCOL:\n"
    "When a finding is based mainly on one artifact class, especially ShimCache:\n"
    "  1. Do not mark it verified yet.\n"
    "  2. Attempt corroboration using at least one independent artifact class.\n"
    "  3. For execution findings, try Prefetch, Amcache, Sysmon Event ID 1, Security 4688, MFT, or USN Journal.\n"
    "  4. For persistence findings, try Scheduled Tasks, Autoruns, Services, Registry hives, MFT, or USN Journal.\n"
    "  5. For logon findings, try Security 4672, 4648, Sysmon, network connections, and related process creation.\n"
    "  6. If corroboration is unavailable or absent, label the finding INCONCLUSIVE and explain the evidence gap.\n"
    "This protocol protects forensic soundness and should be followed before raising confidence.\n\n"

    "INITIAL ACCESS / SYSTEM ZERO PROTOCOL:\n"
    "After persistence, credential dumping, or administrator logon activity is identified:\n"
    "  1. Attempt to identify the earliest suspicious timestamp across ShimCache, Amcache, Sysmon, EVTX, Prefetch, browser history, and user activity artifacts FIRST.\n"
    "  2. Only after exhausting Priority 1 and 2 artifacts, use analyze_mft and analyze_usn_journal with a SPECIFIC filename_filter (e.g. the suspicious executable name). NEVER run them without a filter.\n"
    "  3. Pivot on users, filenames, download paths, browser history, installer names, archive files, scripts, and user-writable directories.\n"
    "  4. Do not guess initial access. If the first observed malicious action is not the true entry point, clearly label it as earliest observed activity.\n"
    "This protocol is mandatory once the agent has enough evidence of compromise to reconstruct the attack timeline.\n\n"

    "STRUCTURED FINDINGS:\n"
    "When you identify a forensic finding, emit it as a structured block:\n"
    "```evidence_claim\n"
    '{"claim": "description of finding", "source": "tool_name_or_artifact", '
    '"supporting": "supporting observation text", '
    '"contradictions": "any contradictory evidence or empty string"}\n'
    "```\n"
    "You may emit multiple evidence_claim blocks in a single response.\n"
    "You must explicitly support or refute your hypotheses after each observation.\n"
    "Continue your natural OBSERVATION -> REASONING -> NEXT ACTION alongside these blocks.\n"
)


# ---------------------------------------------------------------------------
# Evidence Correlation Data Structures
# ---------------------------------------------------------------------------

@dataclass
class EvidenceObject:
    """
    Structured forensic evidence object for corroboration tracking.

    Each finding the agent produces is backed by one of these objects,
    which tracks the claim, all supporting/contradictory evidence,
    confidence score, and verification history.
    """
    finding_id: str
    claim: str
    evidence_sources: list[str] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    supporting_observations: list[str] = field(default_factory=list)
    contradictory_observations: list[str] = field(default_factory=list)
    confidence_score: float = 0.0
    hypothesis_id: str = ""
    verification_actions: list[str] = field(default_factory=list)
    status: str = "hypothesis"  # hypothesis | verified | refuted | inconclusive
    created_at: str = ""
    updated_at: str = ""
    parent_hypothesis_id: str = ""
    attack_mappings: list[dict[str, Any]] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dictionary."""
        return {
            "finding_id": self.finding_id,
            "claim": self.claim,
            "evidence_sources": self.evidence_sources,
            "artifacts": self.artifacts,
            "supporting_observations": self.supporting_observations,
            "contradictory_observations": self.contradictory_observations,
            "evidence_gaps": self.evidence_gaps,
            "confidence_score": round(self.confidence_score, 2),
            "confidence_label": self.confidence_label,
            "hypothesis_id": self.hypothesis_id,
            "verification_actions": self.verification_actions,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "parent_hypothesis_id": self.parent_hypothesis_id,
            "attack_mappings": self.attack_mappings,
        }

    @property
    def confidence_label(self) -> str:
        """Human-readable confidence label."""
        if self.confidence_score >= 0.70:
            return "HIGH"
        elif self.confidence_score >= 0.40:
            return "MEDIUM"
        else:
            return "LOW"


def _parse_sources(source_str: str) -> list[str]:
    """Split comma-separated evidence sources and strip whitespace."""
    if not source_str:
        return []
    parts = [p.strip() for p in source_str.split(",")]
    return [p for p in parts if p]


def _extract_executables_and_tools(text: str) -> set[str]:
    """Extract specific program/tool names from text."""
    import re
    text_lower = text.lower()
    found = set()

    # 1. Extensions
    exes = re.findall(r'\b([\w\.-]+)\.(?:exe|dll|sys|bat|ps1|vbs|bin)\b', text_lower)
    for e in exes:
        found.add(e)

    # 2. Known tools/programs without extension
    known_tools = ["pwdumpx", "pwdump", "powershell", "cmd", "schtasks", "psexec", "psexesvc", "mimikatz", "sysmon", "sysmon64", "wmic", "rundll32", "regsvr32", "reg"]
    for tool in known_tools:
        if re.search(rf'\b{tool}\b', text_lower):
            found.add(tool)

    return found


def _is_absence_claim(claim_text: str) -> bool:
    """Detect if a claim represents an absence of evidence."""
    text = claim_text.lower()
    negatives = [
        "missing", "no results", "absence", "not found", "absent",
        "no evidence", "does not exist", "unable to find", "empty",
        "no event", "no log", "no record", "no 7045", "missing 7045",
        "did not find", "failure to locate", "not present"
    ]
    return any(neg in text for neg in negatives)


def _is_direct_disproof(positive_claim: str, absence_claim: str) -> bool:
    """Determine if an absence claim directly disproves a positive claim."""
    pos_exes = _extract_executables_and_tools(positive_claim)
    abs_exes = _extract_executables_and_tools(absence_claim)

    common_exes = pos_exes.intersection(abs_exes)
    if not common_exes:
        return False

    abs_lower = absence_claim.lower()
    pos_lower = positive_claim.lower()

    for exe in common_exes:
        if any(neg in abs_lower for neg in ["not found", "does not exist", "no such file", "missing", "absent"]):
            # Missing Event IDs are usually evidence gaps, unless positive claim specifically asserted that log event
            if "7045" in abs_lower or "event id" in abs_lower:
                if "7045" in pos_lower or "event id" in pos_lower or "log" in pos_lower:
                    return True
                return False
            return True

    return False


def _extract_specific_entities(text: str) -> set[str]:
    import re
    entities = set()
    text_lower = text.lower()

    # 1. Executables / extensions (excluding generic ones like case files, but keeping main system artifacts)
    executables = re.findall(r'\b[\w\.-]+\.(?:exe|dll|sys|bat|ps1|vbs|bin|hve|evtx|e01)\b', text_lower)
    # Exclude generic setup files if any
    for exe in executables:
        if "case" not in exe:
            entities.add(exe)

    # 2. IP Addresses
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text_lower)
    entities.update(ips)

    # 3. Registry paths or keys
    reg_paths = re.findall(r'\b(?:hklm|hkcu|controlset\d{3}|currentcontrolset|services|sam|software|security|registry|domains\\account\\users|ntuser)\b', text_lower)
    entities.update(reg_paths)

    # 4. File paths or relative paths (containing backslash/slash, excluding cases directory paths)
    paths = re.findall(r'\b[\w\.-]+[\\/][\w\.-]+[\\/\w\.-]*', text_lower)
    for p in paths:
        if "cases" not in p and "evidence" not in p:
            entities.add(p)

    # 5. Usernames (common ones in case files, plus common Windows users)
    usernames = {"administrator", "guest", "rsydow", "rsydow-a", "ftpadmin", "nfury", "dblake", "system", "local service", "network service"}
    for u in usernames:
        if re.search(rf'\b{u}\b', text_lower):
            entities.add(u)

    return entities


def _truncate_tool_result(result_content: Any) -> str:
    raw_text = ""
    if isinstance(result_content, str):
        raw_text = result_content
    elif isinstance(result_content, list):
        parts = []
        for part in result_content:
            if isinstance(part, str):
                parts.append(part)
            elif hasattr(part, "text") and part.text:
                parts.append(part.text)
            elif isinstance(part, dict) and "text" in part:
                parts.append(part["text"])
        raw_text = "".join(parts)
    else:
        raw_text = str(result_content)

    try:
        data = json.loads(raw_text)
        if isinstance(data, dict) and "entries" in data and isinstance(data["entries"], list):
            entries = data["entries"]
            if len(entries) > 20:
                truncated_data = {}
                for k, v in data.items():
                    if k != "entries":
                        truncated_data[k] = v
                truncated_data["entries"] = entries[:20]
                total = len(entries)
                truncated_data["note"] = f"Showing first 20 entries. The full output of {total} entries was recorded in the audit log."
                return json.dumps(truncated_data)
    except Exception:
        pass

    return raw_text


def _extract_text_content(content: Any) -> str:
    """Extract raw text from tool result content, handling strings, lists, or dicts."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif hasattr(part, "text") and part.text:
                parts.append(part.text)
            elif isinstance(part, dict) and "text" in part:
                parts.append(part["text"])
        return "".join(parts)
    return str(content)


@dataclass
class ObservedEvidenceItem:
    source_tool: str
    artifact_family: str
    raw_entry: dict[str, Any]
    summary: str
    entities: set[str] = field(default_factory=set)
    executables: set[str] = field(default_factory=set)
    service_names: set[str] = field(default_factory=set)
    paths: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    timestamp: str | None = None
    attack_concepts: set[str] = field(default_factory=set)


class ObservedEvidenceStore:
    def __init__(self) -> None:
        self.items: list[ObservedEvidenceItem] = []

    def add_item(self, item: ObservedEvidenceItem) -> None:
        self.items.append(item)

    def add_from_tool_output(self, tool_name: str, result_content: Any) -> None:
        """Parse structured tool output JSON and extract observed evidence."""
        try:
            raw_text = _extract_text_content(result_content)
            data = json.loads(raw_text)
            if not isinstance(data, dict):
                return
            entries = data.get("entries", [])
            if not isinstance(entries, list):
                return

            for entry in entries:
                self._parse_entry(tool_name, entry)
        except Exception:
            pass

    def _parse_entry(self, tool_name: str, entry: dict[str, Any]) -> None:
        import re
        executables = set()
        service_names = set()
        paths = set()
        hashes = set()
        users = set()
        concepts = set()
        timestamp = None
        summary_parts = []

        # Extract common fields
        for val in entry.values():
            if isinstance(val, str):
                # Hash match
                m_hash = re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', val)
                hashes.update([h.lower() for h in m_hash])
                # Executable match
                m_exes = re.findall(r'\b([\w\.-]+\.(?:exe|dll|sys|bat|ps1|vbs|bin))\b', val.lower())
                executables.update(m_exes)

        # Normalize specific tools
        artifact_family = get_source_artifact_class(tool_name)

        if tool_name == "analyze_amcache":
            file_name = entry.get("file_name") or ""
            full_path = entry.get("full_path") or ""
            sha1 = entry.get("sha1") or ""
            timestamp = entry.get("first_run") or entry.get("last_modified")

            if file_name:
                executables.add(file_name.lower())
            if full_path:
                paths.add(full_path.lower())
                executables.add(os.path.basename(full_path).lower())
            if sha1:
                hashes.add(sha1.lower())
            summary_parts.append(f"Amcache entry for {file_name or full_path}")
            concepts.add("execution")

        elif tool_name == "analyze_shimcache":
            path = entry.get("path") or ""
            timestamp = entry.get("last_modified_time")
            if path:
                paths.add(path.lower())
                executables.add(os.path.basename(path).lower())
            summary_parts.append(f"Shimcache entry for {path}")
            concepts.add("execution")

        elif tool_name == "analyze_prefetch":
            executable = entry.get("executable") or entry.get("source_file") or ""
            timestamp = entry.get("last_run")
            if executable:
                executables.add(executable.lower())
            summary_parts.append(f"Prefetch execution of {executable}")
            concepts.add("execution")

        elif tool_name == "analyze_services":
            service_name = entry.get("service_name") or ""
            display_name = entry.get("display_name") or ""
            image_path = entry.get("image_path") or ""

            if service_name:
                service_names.add(service_name.lower())
            if display_name:
                service_names.add(display_name.lower())
            if image_path:
                paths.add(image_path.lower())
                m_exes = re.findall(r'\b([\w\.-]+\.(?:exe|dll|sys|bat|ps1|vbs|bin))\b', image_path.lower())
                executables.update(m_exes)
            summary_parts.append(f"Windows service {service_name} registered ({image_path})")
            concepts.add("services")
            concepts.add("persistence")

        elif tool_name == "analyze_sysmon":
            eid = str(entry.get("event_id", ""))
            timestamp = entry.get("timestamp")

            image = entry.get("image") or ""
            cmd = entry.get("command_line") or ""
            user = entry.get("user") or ""

            if image:
                executables.add(os.path.basename(image).lower())
                paths.add(image.lower())
            if cmd:
                m_exes = re.findall(r'\b([\w\.-]+\.(?:exe|dll|sys|bat|ps1|vbs|bin))\b', cmd.lower())
                executables.update(m_exes)
            if user:
                users.add(user.lower())
            summary_parts.append(f"Sysmon Event {eid} observed")
            concepts.add("sysmon")
            if eid == "1":
                concepts.add("execution")
            elif eid == "3":
                concepts.add("network")

        elif tool_name == "analyze_evtx":
            eid = str(entry.get("event_id", ""))
            timestamp = entry.get("timestamp")

            if eid == "7045":
                service_name = entry.get("service_name") or ""
                image_path = entry.get("image_path") or ""
                if service_name:
                    service_names.add(service_name.lower())
                if image_path:
                    paths.add(image_path.lower())
                    m_exes = re.findall(r'\b([\w\.-]+\.(?:exe|dll|sys|bat|ps1|vbs|bin))\b', image_path.lower())
                    executables.update(m_exes)
                summary_parts.append(f"EVTX Service Creation: {service_name}")
                concepts.add("services")
                concepts.add("persistence")
            else:
                summary_parts.append(f"EVTX Event {eid} observed")
                if eid in ["4624", "4625"]:
                    concepts.add("logon")

        elif tool_name == "analyze_powershell_logs":
            eid = str(entry.get("event_id", ""))
            timestamp = entry.get("timestamp")
            script_text = entry.get("script_block_text", "") or ""
            if script_text:
                m_exes = re.findall(r'\b([\w\.-]+\.(?:exe|dll|sys|bat|ps1|vbs|bin))\b', script_text.lower())
                executables.update(m_exes)
            summary_parts.append(f"PowerShell Log Event {eid} observed")
            concepts.add("powershell")
            concepts.add("execution")

        elif tool_name == "analyze_autoruns":
            entry_name = entry.get("entry") or ""
            launch_str = entry.get("launch_string") or ""
            path = entry.get("path") or ""

            if entry_name:
                service_names.add(entry_name.lower())
            if launch_str:
                paths.add(launch_str.lower())
                m_exes = re.findall(r'\b([\w\.-]+\.(?:exe|dll|sys|bat|ps1|vbs|bin))\b', launch_str.lower())
                executables.update(m_exes)
            if path:
                paths.add(path.lower())
            summary_parts.append(f"Autorun entry: {entry_name} -> {launch_str}")
            concepts.add("autoruns")
            concepts.add("persistence")

        elif tool_name == "analyze_scheduled_tasks":
            task_name = entry.get("task_name") or ""
            action = entry.get("action") or ""
            path = entry.get("path") or ""

            if task_name:
                service_names.add(task_name.lower())
            if action:
                m_exes = re.findall(r'\b([\w\.-]+\.(?:exe|dll|sys|bat|ps1|vbs|bin))\b', action.lower())
                executables.update(m_exes)
            if path:
                paths.add(path.lower())
            summary_parts.append(f"Scheduled task: {task_name} -> {action}")
            concepts.add("scheduled_tasks")
            concepts.add("persistence")

        elif tool_name == "analyze_sam_users":
            username = entry.get("username") or ""
            if username:
                users.add(username.lower())
            summary_parts.append(f"SAM user account: {username}")
            concepts.add("sam_users")

        elif tool_name == "analyze_network_connections":
            proto = entry.get("protocol") or ""
            local_addr = entry.get("local_address") or ""
            remote_addr = entry.get("remote_address") or ""
            summary_parts.append(f"Network Connection: {proto} {local_addr} -> {remote_addr}")
            concepts.add("network")

        else:
            summary_parts.append(f"Observed artifact in {tool_name}")

        # Gather general entities
        entities = set()
        entities.update(executables)
        entities.update(service_names)
        entities.update(hashes)
        entities.update(users)
        for p in paths:
            entities.add(os.path.basename(p))

        self.add_item(ObservedEvidenceItem(
            source_tool=tool_name,
            artifact_family=artifact_family,
            raw_entry=entry,
            summary=" ".join(summary_parts),
            entities=entities,
            executables=executables,
            service_names=service_names,
            paths=paths,
            hashes=hashes,
            users=users,
            timestamp=timestamp,
            attack_concepts=concepts
        ))


def _is_narrow_fact(claim_text: str) -> bool:
    """Check if the claim represents a narrow forensic fact."""
    text = claim_text.lower()
    narrow_keywords = [
        "present on disk", "was registered as a windows service", "windows service registered",
        "registered as a service", "file exists", "path was", "key was", "created at",
        "modified at", "hash is", "sha1", "entry existed", "was present", "file is present",
        "was registered", "created service", "scheduled task registered"
    ]
    return any(kw in text for kw in narrow_keywords) or "registered as a Windows service" in claim_text


def _is_broad_interpretation(claim_text: str) -> bool:
    """Check if the claim represents a broad attack interpretation."""
    text = claim_text.lower()
    broad_keywords = [
        "was used for", "remote execution", "lateral movement", "compromise", "adversary",
        "psexec-style remote execution is suspected", "credential dumping activity",
        "powershell download/execution suspected", "persistence via", "execution suspected",
        "suspicious execution", "exfiltration", "malicious activity"
    ]
    return any(kw in text for kw in broad_keywords)


def _split_broad_claim(claim_text: str) -> list[str]:
    """Split broad attack interpretations into narrow forensic facts and broad suspected claims."""
    text_lower = claim_text.lower()

    if "psexec" in text_lower or "psexesvc" in text_lower:
        if any(kw in text_lower for kw in ["used for", "persistence", "remote execution", "installed"]):
            return [
                "PSEXESVC.exe was present on disk.",
                "PSEXESVC was registered as a Windows service.",
                "PsExec-style remote execution is suspected."
            ]

    if "mimikatz" in text_lower or "pwdump" in text_lower:
        if any(kw in text_lower for kw in ["used to", "used for", "dump credentials", "credential dumping"]):
            return [
                "PWDumpX/mimikatz credential dumper was present on disk.",
                "Credential dumping activity was suspected/observed."
            ]

    if "scheduled task" in text_lower or "schtasks" in text_lower:
        if "persistence" in text_lower or "used for" in text_lower:
            return [
                "A scheduled task was created.",
                "Persistence via scheduled task is suspected."
            ]

    return [claim_text]


def _is_direct_match_strict(eo: EvidenceObject, item: ObservedEvidenceItem) -> bool:
    """Determine if an observed evidence item strictly directly disproves or supports a finding claim."""
    claim_text = eo.claim.lower()

    # 1. Executable name match
    pos_exes = _extract_executables_and_tools(eo.claim)
    for obs in eo.supporting_observations:
        pos_exes.update(_extract_executables_and_tools(obs))

    if pos_exes and item.executables:
        common_exes = pos_exes.intersection(item.executables)
        if common_exes:
            return True

    # 2. Service name match
    if item.service_names:
        words = re.findall(r'\b[a-zA-Z0-9_-]{4,}\b', claim_text)
        for w in words:
            if w in ["execution", "service", "registered", "present", "disk", "remote", "suspected", "lateral", "movement"]:
                continue
            if w in item.service_names:
                return True

    # 3. Full path match
    claim_paths = re.findall(r'\b[\w\.-]+[\\/][\w\.-]+[\\/\w\.-]*', claim_text)
    if claim_paths and item.paths:
        claim_paths_clean = {p.lower() for p in claim_paths}
        if claim_paths_clean.intersection(item.paths):
            return True

    # 4. Hash match
    claim_hashes = re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', claim_text)
    if claim_hashes and item.hashes:
        claim_hashes_clean = {h.lower() for h in claim_hashes}
        if claim_hashes_clean.intersection(item.hashes):
            return True

    # 5. Username match
    if item.users:
        for u in item.users:
            if re.search(rf'\b{u}\b', claim_text):
                return True

    # 6. Precise attack concept + concrete entity
    if "sysmon" in claim_text and "sysmon" in item.attack_concepts:
        shared = [ent for ent in item.entities if ent in claim_text]
        if shared and not any(s in ["sysmon", "exe", "sysmon64", "xml"] for s in shared):
            return True

    if "scheduled task" in claim_text and "scheduled_tasks" in item.attack_concepts:
        shared = [ent for ent in item.entities if ent in claim_text]
        if shared:
            return True

    return False


def auto_corroborate_all_findings(correlator: "EvidenceCorrelator", observed_store: ObservedEvidenceStore) -> None:
    """Scan each finding and attach previously observed evidence only when there is a direct match."""
    for eo in correlator.get_all():
        for item in observed_store.items:
            if _is_direct_match_strict(eo, item):
                source = item.source_tool
                if source and source not in eo.evidence_sources:
                    eo.evidence_sources.append(source)

                obs_summary = f"Direct observation from {source}: {item.summary}"
                if obs_summary not in eo.supporting_observations:
                    eo.supporting_observations.append(obs_summary)

                if item.raw_entry not in eo.artifacts:
                    eo.artifacts.append(item.raw_entry)

                eo.updated_at = datetime.now(timezone.utc).isoformat()
                eo.confidence_score = correlator._calculate_confidence(eo)
                eo.attack_mappings = MitreAttackMapper.map_finding(eo.claim, eo.evidence_sources, eo.supporting_observations)


class EvidenceCorrelator:
    """
    Aggregates and correlates evidence across multiple tool outputs.

    Implements confidence scoring rules:
        - 1 source = low confidence (base 0.25)
        - 2 independent sources = medium confidence (base 0.50)
        - 3+ corroborating sources = high confidence (base 0.75)

    Modifiers:
        - Each contradictory observation: -0.15
        - Failed verification attempt: -0.10
        - Successful verification: +0.10
        - DFIR validation warning: -0.05
    """

    def __init__(self) -> None:
        self.evidence: dict[str, EvidenceObject] = {}
        self._hypothesis_counter = 0
        self.observed_store = ObservedEvidenceStore()

    def _next_hypothesis_id(self) -> str:
        self._hypothesis_counter += 1
        return f"H-{self._hypothesis_counter:03d}"

    def create_evidence(self, claim: str, source: str = "",
                        artifact: dict[str, Any] | None = None,
                        supporting: str = "") -> EvidenceObject:
        """Create a new evidence object for a forensic claim."""
        now = datetime.now(timezone.utc).isoformat()
        sources = _parse_sources(source)
        eo = EvidenceObject(
            finding_id=str(uuid.uuid4())[:8],
            claim=claim,
            evidence_sources=sources,
            artifacts=[artifact] if artifact else [],
            supporting_observations=[supporting] if supporting else [],
            hypothesis_id=self._next_hypothesis_id(),
            created_at=now,
            updated_at=now,
        )
        eo.confidence_score = self._calculate_confidence(eo)
        eo.attack_mappings = MitreAttackMapper.map_finding(eo.claim, eo.evidence_sources, eo.supporting_observations)
        self.evidence[eo.finding_id] = eo
        return eo

    def add_corroboration(self, finding_id: str, source: str,
                          observation: str,
                          artifact: dict[str, Any] | None = None) -> float:
        """Add corroborating evidence to an existing finding. Returns new confidence."""
        eo = self.evidence.get(finding_id)
        if not eo:
            return 0.0
        for src in _parse_sources(source):
            if src and src not in eo.evidence_sources:
                eo.evidence_sources.append(src)
        if observation:
            eo.supporting_observations.append(observation)
        if artifact:
            eo.artifacts.append(artifact)
        eo.updated_at = datetime.now(timezone.utc).isoformat()
        eo.confidence_score = self._calculate_confidence(eo)
        eo.attack_mappings = MitreAttackMapper.map_finding(eo.claim, eo.evidence_sources, eo.supporting_observations)
        return eo.confidence_score

    def add_contradiction(self, finding_id: str, observation: str, logger: Any = None) -> float:
        """Add contradictory evidence and spawn a child hypothesis. Returns new confidence."""
        eo = self.evidence.get(finding_id)
        if not eo:
            return 0.0
        eo.contradictory_observations.append(observation)
        eo.updated_at = datetime.now(timezone.utc).isoformat()
        eo.confidence_score = self._calculate_confidence(eo)

        # Create a new child hypothesis branch
        child_claim = f"Alternative explanation for contradiction in {eo.hypothesis_id}: {observation}"
        now = datetime.now(timezone.utc).isoformat()
        child_eo = EvidenceObject(
            finding_id=str(uuid.uuid4())[:8],
            claim=child_claim,
            evidence_sources=eo.evidence_sources.copy(),
            supporting_observations=[observation],
            hypothesis_id=self._next_hypothesis_id(),
            parent_hypothesis_id=eo.hypothesis_id,
            created_at=now,
            updated_at=now,
        )
        child_eo.confidence_score = self._calculate_confidence(child_eo)
        child_eo.attack_mappings = MitreAttackMapper.map_finding(child_eo.claim, child_eo.evidence_sources, child_eo.supporting_observations)
        self.evidence[child_eo.finding_id] = child_eo

        if logger:
            logger.log_evidence_created(child_eo)

        return eo.confidence_score

    def record_verification(self, finding_id: str, action: str,
                            success: bool) -> float:
        """Record a verification action and adjust confidence."""
        eo = self.evidence.get(finding_id)
        if not eo:
            return 0.0
        eo.verification_actions.append(action)
        modifier = 0.10 if success else -0.10
        eo.confidence_score = max(0.0, min(1.0, eo.confidence_score + modifier))
        eo.updated_at = datetime.now(timezone.utc).isoformat()
        return eo.confidence_score

    def apply_dfir_penalty(self, finding_id: str, warning: str) -> float:
        """Apply a DFIR validation penalty."""
        eo = self.evidence.get(finding_id)
        if not eo:
            return 0.0
        eo.confidence_score = max(0.0, eo.confidence_score - 0.05)
        eo.updated_at = datetime.now(timezone.utc).isoformat()
        return eo.confidence_score

    def finalize(self, finding_id: str, status: str) -> None:
        """Set the final status of a finding after verification."""
        eo = self.evidence.get(finding_id)
        if eo:
            eo.status = status
            eo.updated_at = datetime.now(timezone.utc).isoformat()

    def find_related(self, claim_text: str) -> list[EvidenceObject]:
        """Find evidence objects whose claims overlap with the given claim_text by sharing specific entities, executables, or attack claims."""
        results = []
        new_exes = _extract_executables_and_tools(claim_text)

        def get_attack_claims(text: str) -> set[str]:
            text_lower = text.lower()
            concepts = set()
            if any(kw in text_lower for kw in ["pwdump", "pwdumpx", "mimikatz", "credential dump", "lsass"]):
                concepts.add("credential_dumping")
            if any(kw in text_lower for kw in ["schtasks", "scheduled task", "task scheduler"]):
                concepts.add("scheduled_tasks")
            if any(kw in text_lower for kw in ["service", "psexesvc"]):
                concepts.add("services")
            if any(kw in text_lower for kw in ["psexec", "lateral movement", "rdp", "remote desktop"]):
                concepts.add("lateral_movement")
            if any(kw in text_lower for kw in ["powershell", "ps1"]):
                concepts.add("powershell")
            if any(kw in text_lower for kw in ["cmd.exe", "cmd"]):
                concepts.add("cmd")
            if any(kw in text_lower for kw in ["registry run", "run key", "startup folder", "reg.exe", "reg"]):
                concepts.add("registry")
            return concepts

        new_concepts = get_attack_claims(claim_text)
        new_entities = _extract_specific_entities(claim_text)

        for eo in self.evidence.values():
            eo_exes = _extract_executables_and_tools(eo.claim)
            eo_concepts = get_attack_claims(eo.claim)

            # Check for executable overlap
            exe_overlap = new_exes.intersection(eo_exes)
            concept_overlap = new_concepts.intersection(eo_concepts)

            is_related = False

            if exe_overlap:
                is_related = True
            elif concept_overlap:
                is_related = True
            else:
                # If they do not share a specific executable or a precise concept/attack claim,
                # we do NOT merge them, even if they share generic entities like 'system' or 'administrator' or '.exe'.
                is_related = False

            # If both mention tools from the distinct list, they must share the specific executable or precise attack claim.
            # E.g. PWDumpX vs PowerShell vs PsExec vs cmd.exe vs schtasks.exe vs reg.exe
            distinct_categories = ["pwdump", "powershell", "cmd", "schtasks", "psexec", "reg"]
            claim_cats = {cat for cat in distinct_categories if any(cat in val for val in new_exes) or re.search(rf'\b{cat}\b', claim_text.lower())}
            eo_cats = {cat for cat in distinct_categories if any(cat in val for val in eo_exes) or re.search(rf'\b{cat}\b', eo.claim.lower())}

            if claim_cats and eo_cats and claim_cats != eo_cats:
                # Different tools mentioned! Do not merge unless they share the same precise attack claim.
                if not concept_overlap:
                    is_related = False

            if is_related:
                eo_entities = _extract_specific_entities(eo.claim)
                if new_entities.intersection(eo_entities) or exe_overlap or concept_overlap:
                    results.append(eo)
        return results

    def get_all(self) -> list[EvidenceObject]:
        """Return all evidence objects."""
        return list(self.evidence.values())

    def get_summary(self) -> dict[str, Any]:
        """Return a summary of all evidence for reporting."""
        all_ev = self.get_all()
        return {
            "total_findings": len(all_ev),
            "by_status": {
                "verified": len([e for e in all_ev if e.status == "verified"]),
                "refuted": len([e for e in all_ev if e.status == "refuted"]),
                "inconclusive": len([e for e in all_ev if e.status == "inconclusive"]),
                "hypothesis": len([e for e in all_ev if e.status == "hypothesis"]),
            },
            "by_confidence": {
                "high": len([e for e in all_ev if e.confidence_label == "HIGH"]),
                "medium": len([e for e in all_ev if e.confidence_label == "MEDIUM"]),
                "low": len([e for e in all_ev if e.confidence_label == "LOW"]),
            },
        }

    def _calculate_confidence(self, eo: EvidenceObject) -> float:
        """Calculate confidence based on source count and directness modifiers."""
        direct_sources = set()
        for src in eo.evidence_sources:
            for item in self.observed_store.items:
                if item.source_tool == src:
                    if _is_direct_match_strict(eo, item):
                        direct_sources.add(src)
                        break

        unique_sources = set(eo.evidence_sources)
        indirect_sources = unique_sources.difference(direct_sources)

        artifact_families = set()
        for src in direct_sources:
            cls = get_source_artifact_class(src, eo.claim + " " + " ".join(eo.supporting_observations))
            artifact_families.add(cls)

        n_direct = len(direct_sources)
        n_families = len(artifact_families)

        # Base confidence calculation based on direct independent sources
        # * 1 direct source: low confidence
        # * 2 direct independent sources: medium confidence
        # * 3+ direct independent sources across artifact families: high confidence
        if n_direct >= 3 and n_families >= 2:
            base = 0.75
        elif n_direct == 2:
            base = 0.50
        elif n_direct == 1:
            base = 0.25
        else:
            base = 0.10

        # Indirect / generic sources add little or no confidence
        base += len(indirect_sources) * 0.02

        # Supporting observations beyond base direct sources add small boost
        extra_support = max(0, len(eo.supporting_observations) - n_direct)
        base += extra_support * 0.02

        # Contradictions directly conflicting reduce confidence
        base -= len(eo.contradictory_observations) * 0.15

        # Apply verification modifier based on status
        if eo.status == "verified":
            base += 0.10
        elif eo.status in ("refuted", "inconclusive"):
            base -= 0.10

        # Caps:
        claim_lower = eo.claim.lower()

        # * Narrow facts with 3+ direct independent artifacts may reach 0.70-0.85
        if _is_narrow_fact(eo.claim):
            if n_direct >= 3:
                base = min(max(0.70, base), 0.85)
            elif n_direct == 2:
                base = min(base, 0.65)
            else:
                base = min(base, 0.30)
        # * Broad interpretation claims should cap around 0.55 unless directly supported
        elif _is_broad_interpretation(eo.claim):
            has_direct_support = any(src in direct_sources for src in ["analyze_sysmon", "analyze_evtx", "run_tshark_summary", "analyze_powershell_logs", "analyze_prefetch"])
            if not has_direct_support:
                base = min(base, 0.55)
            else:
                base = min(base, 0.70)

        # * Lateral movement claims should cap around 0.35 unless supported by Logon Type 3/10 or network/Sysmon
        if "lateral movement" in claim_lower:
            has_logon = any(type_str in claim_lower or any(type_str in obs.lower() for obs in eo.supporting_observations)
                            for type_str in ["logon type 3", "logon type 10", "type 3", "type 10"])
            has_network = "run_tshark_summary" in direct_sources or "analyze_network_connections" in direct_sources
            has_sysmon_net = "analyze_sysmon" in direct_sources and any("network" in obs.lower() for obs in eo.supporting_observations)

            if not (has_logon or has_network or has_sysmon_net):
                base = min(base, 0.35)
            else:
                base = min(base, 0.60)

        return max(0.0, min(1.0, base))


class DFIRValidator:
    """
    Validates forensic findings against DFIR best practices.

    Rules:
        - SINGLE_ARTIFACT: Warn when a claim relies on a single artifact
        - EXECUTION_CORROBORATION: Execution claims need >= 2 artifact types
        - LATERAL_MOVEMENT_CORROBORATION: Lateral movement needs network + host
        - PERSISTENCE_CORROBORATION: Persistence claims need registry + filesystem
        - CONTRADICTION_SIGNAL: Contradictions are investigation signals
        - TIMESTAMP_CONSISTENCY: Cross-check timestamp consistency
        - PRIVILEGE_ESCALATION_CORROBORATION: Privilege escalation needs multiple independent sources
    """

    EXECUTION_KEYWORDS = [
        "executed", "execution", "ran", "launched", "psexec",
        "powershell", "cmd.exe", "wmic", "rundll32", "regsvr32",
    ]
    LATERAL_KEYWORDS = [
        "lateral movement", "rdp", "psexec remote", "wmi remote",
        "smb", "pass-the-hash", "pass the hash", "winrm",
    ]
    PERSISTENCE_KEYWORDS = [
        "persistence", "autorun", "scheduled task", "service creation",
        "registry run key", "startup folder", "boot",
    ]

    def validate(self, evidence: EvidenceObject) -> list[dict[str, str]]:
        """
        Run all validation rules against a single evidence object.
        Returns a list of {rule, severity, message} dictionaries.
        """
        warnings: list[dict[str, str]] = []
        claim_lower = evidence.claim.lower()
        unique_sources = set(evidence.evidence_sources)

        # Rule 1: Single artifact warning
        if len(unique_sources) < 2:
            warnings.append({
                "rule": "SINGLE_ARTIFACT",
                "severity": "WARNING",
                "message": (
                    f"Finding '{evidence.claim[:60]}' relies on a single evidence source. "
                    "DFIR best practice requires corroboration from independent artifacts."
                ),
            })

        # Rule 2: Execution corroboration
        if any(kw in claim_lower for kw in self.EXECUTION_KEYWORDS):
            if len(unique_sources) < 2:
                warnings.append({
                    "rule": "EXECUTION_CORROBORATION",
                    "severity": "IMPORTANT",
                    "message": (
                        f"Execution claim '{evidence.claim[:60]}' requires >= 2 independent "
                        "artifact types (e.g., Prefetch + Amcache, Event Log + Shimcache)."
                    ),
                })

        # Rule 3: Lateral movement corroboration
        if any(kw in claim_lower for kw in self.LATERAL_KEYWORDS):
            has_network = any(
                "network" in s.lower() or "pcap" in s.lower() or "tshark" in s.lower()
                for s in unique_sources
            )
            has_host = any(
                any(k in s.lower() for k in ["prefetch", "amcache", "shimcache", "userassist", "recentapps", "sysmon", "evtx", "powershell", "usn"])
                for s in unique_sources
            )
            if not (has_network and has_host):
                warnings.append({
                    "rule": "LATERAL_MOVEMENT_CORROBORATION",
                    "severity": "IMPORTANT",
                    "message": (
                        f"Lateral movement claim '{evidence.claim[:60]}' should have both "
                        "network evidence (pcap/netflow) and host evidence (event logs/registry)."
                    ),
                })

        # Rule 4: Persistence corroboration
        if any(kw in claim_lower for kw in self.PERSISTENCE_KEYWORDS):
            has_registry = any(
                any(k in s.lower() for k in ["userassist", "recentapps", "shimcache", "amcache"])
                for s in unique_sources
            )
            has_filesystem = any(
                any(k in s.lower() for k in ["prefetch", "usn_journal", "list_case_evidence"])
                for s in unique_sources
            )
            if not (has_registry and has_filesystem):
                warnings.append({
                    "rule": "PERSISTENCE_CORROBORATION",
                    "severity": "IMPORTANT",
                    "message": (
                        f"Persistence claim '{evidence.claim[:60]}' should be corroborated "
                        "across registry and filesystem artifacts."
                    ),
                })

        # Rule 5: Contradiction signal
        if evidence.contradictory_observations:
            warnings.append({
                "rule": "CONTRADICTION_SIGNAL",
                "severity": "INFO",
                "message": (
                    f"Finding has {len(evidence.contradictory_observations)} contradictory "
                    "observation(s). Treat as investigation signals -- pursue additional evidence."
                ),
            })

        # Rule 7: Privilege escalation corroboration
        PRIVILEGE_KEYWORDS = [
            "privilege escalation", "bypass uac", "special privilege", "administrator", "system",
        ]
        if any(kw in claim_lower for kw in PRIVILEGE_KEYWORDS):
            if len(unique_sources) < 2:
                warnings.append({
                    "rule": "PRIVILEGE_ESCALATION_CORROBORATION",
                    "severity": "IMPORTANT",
                    "message": (
                        f"Privilege escalation claim '{evidence.claim[:60]}' requires corroboration "
                        "across multiple sources (e.g., Security Event Log + Sysmon, or Registry)."
                    ),
                })

        return warnings


# ---------------------------------------------------------------------------
# Artifact-Aware Classification & Suggester
# ---------------------------------------------------------------------------

def get_source_artifact_class(source: str, context: str = "") -> str:
    """
    Categorize forensic tools/evidence sources into specific DFIR artifact classes.
    """
    source_lower = source.lower()

    if "analyze_amcache" in source_lower:
        return "amcache"
    if "analyze_shimcache" in source_lower:
        return "shimcache"
    if "analyze_prefetch" in source_lower:
        return "prefetch"
    if "analyze_services" in source_lower:
        return "services_registry"
    if "analyze_sysmon" in source_lower:
        return "sysmon_event_log"
    if "analyze_powershell_logs" in source_lower:
        return "powershell_event_log"
    if "analyze_evtx" in source_lower:
        return "windows_event_log"
    if "analyze_autoruns" in source_lower:
        return "autoruns"
    if "analyze_scheduled_tasks" in source_lower:
        return "scheduled_tasks"
    if "analyze_network_connections" in source_lower or "run_tshark_summary" in source_lower:
        return "network"
    if "analyze_mft" in source_lower:
        return "mft"
    if "analyze_usn_journal" in source_lower:
        return "usn_journal"
    if "analyze_sam_users" in source_lower:
        return "sam_users"

    # Fallback to context or generic mapping
    context_lower = context.lower()
    if any(k in source_lower for k in ["tshark", "pcap", "network"]) or any(k in context_lower for k in ["lateral movement", "rdp", "smb", "winrm", "psexec"]):
        return "network"
    if any(k in context_lower for k in ["persistence", "autorun", "service creation", "scheduled task", "schtasks", "run key", "startup folder"]):
        return "persistence_artifacts"
    if any(k in context_lower for k in ["privilege escalation", "bypass uac", "administrator", "special privilege", "4672", "system privilege"]):
        return "privilege_escalation_artifacts"

    return "execution_artifacts"


def _generate_corroboration_prompt(evidence: EvidenceObject) -> str:
    """
    Suggests specific forensic tools to run to corroborate a claim,
    based on its predicted artifact class.
    """
    cls = get_source_artifact_class(evidence.claim, evidence.claim + " " + " ".join(evidence.supporting_observations))

    prompt = (
        f"The finding '{evidence.claim}' currently has LOW confidence ({evidence.confidence_score:.0%}). "
        f"To verify this claim, you should gather corroborating evidence from another independent source. "
    )

    if cls in ("execution_artifacts", "amcache", "shimcache", "prefetch"):
        prompt += (
            "Since this is an execution claim, run analyze_prefetch, analyze_amcache, "
            "analyze_shimcache, analyze_userassist, or analyze_recentapps. For example, "
            "if you only checked Prefetch, run analyze_amcache or analyze_shimcache to see "
            "if the program is registered there."
        )
    elif cls in ("persistence_artifacts", "services_registry", "autoruns", "scheduled_tasks"):
        prompt += (
            "Since this is a persistence claim, run analyze_evtx (log_name='System', event_ids='7045') "
            "to check for service installations, analyze_scheduled_tasks, or analyze_autoruns. "
            "If you need USN Journal data, use analyze_usn_journal with a specific filename_filter "
            "(e.g. the suspicious executable name). Do NOT run broad USN or MFT scans without filters."
        )
    elif cls in ("lateral_movement_artifacts", "network"):
        prompt += (
            "Since this is a lateral movement claim, run run_tshark_summary to check network packets, "
            "or run analyze_evtx (log_name='Security', event_ids='4624,4625') to search for "
            "successful or failed remote logon events (Logon Type 3 or 10)."
        )
    elif cls in ("privilege_escalation_artifacts",):
        prompt += (
            "Since this is a privilege escalation claim, run analyze_evtx (log_name='Security', event_ids='4672') "
            "to check for special privilege assignments, or check analyze_sysmon for process injection (Event ID 8)."
        )
    else:
        prompt += "Run alternative registry or event log analysis tools to find corroborating events."

    return prompt


# ---------------------------------------------------------------------------
# Investigation Planner
# ---------------------------------------------------------------------------

class InvestigationPlanner:
    """
    Generates structured investigation plans from hypotheses and logs them.
    Each plan contains hypothesis, required artifacts, tool selection rationale, and expected evidence.
    """
    def __init__(self) -> None:
        self.plans: list[dict[str, Any]] = []

    def add_plan(self, hypothesis: str, required_artifacts: list[str], tool_selection: str, expected_evidence: str) -> dict[str, Any]:
        plan = {
            "plan_id": f"P-{len(self.plans) + 1:03d}",
            "hypothesis": hypothesis,
            "required_artifacts": required_artifacts,
            "tool_selection": tool_selection,
            "expected_evidence": expected_evidence,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self.plans.append(plan)
        return plan


# ---------------------------------------------------------------------------
# Forensic Timeline Reconstruction
# ---------------------------------------------------------------------------

class ForensicTimeline:
    """
    Collects, normalizes, and analyzes chronological events from forensic artifacts.
    Detects logical anomalies (e.g. execution before creation) and calculates a consistency score.
    """
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.contradictions: list[str] = []
        self._last_score: float = 1.0

    def add_events_from_tool_output(self, tool_name: str, result_str: Any) -> None:
        """Parses tool output JSON and extracts timestamped events."""
        try:
            raw_text = _extract_text_content(result_str)
            data = json.loads(raw_text)
            if not isinstance(data, dict):
                return
            entries = data.get("entries", [])
            if not isinstance(entries, list):
                return

            for entry in entries:
                if tool_name == "analyze_prefetch":
                    exec_name = entry.get("executable") or entry.get("source_file", "Unknown")
                    if entry.get("last_run"):
                        self._add_event(entry["last_run"], "prefetch_execution", f"Prefetch execution of {exec_name}", {"executable": exec_name, "run_count": entry.get("run_count")})
                    for prev in entry.get("previous_runs", []):
                        if prev:
                            self._add_event(prev, "prefetch_execution", f"Previous Prefetch execution of {exec_name}", {"executable": exec_name})

                elif tool_name == "analyze_amcache":
                    file_name = entry.get("file_name") or entry.get("full_path", "Unknown")
                    if entry.get("first_run"):
                        self._add_event(entry["first_run"], "amcache_first_run", f"Amcache first run/install of {file_name}", {"file": file_name, "sha1": entry.get("sha1")})

                elif tool_name == "analyze_shimcache":
                    path = entry.get("path") or "Unknown"
                    if entry.get("last_modified_time"):
                        self._add_event(entry["last_modified_time"], "shimcache_modified", f"Shimcache last modified for {path}", {"path": path})

                elif tool_name == "analyze_userassist":
                    prog = entry.get("program_name") or "Unknown"
                    user = entry.get("username", "Unknown")
                    if entry.get("last_executed"):
                        self._add_event(entry["last_executed"], "userassist_execution", f"UserAssist execution of {prog} by {user}", {"program": prog, "user": user, "run_count": entry.get("run_count")})

                elif tool_name == "analyze_recentapps":
                    app = entry.get("app_path") or entry.get("app_id", "Unknown")
                    user = entry.get("username", "Unknown")
                    if entry.get("last_accessed"):
                        self._add_event(entry["last_accessed"], "recentapps_access", f"RecentApps access of {app} by {user}", {"app": app, "user": user})

                elif tool_name == "analyze_sysmon":
                    eid = entry.get("event_id")
                    desc = entry.get("map_description") or f"Sysmon Event {eid}"
                    if entry.get("timestamp"):
                        self._add_event(entry["timestamp"], f"sysmon_{eid}", f"Sysmon [{eid}] {desc} - {entry.get('payload', '')[:100]}", entry)

                elif tool_name == "analyze_evtx":
                    eid = entry.get("event_id")
                    desc = entry.get("map_description") or f"Event Log {eid}"
                    if entry.get("timestamp"):
                        self._add_event(entry["timestamp"], f"evtx_{eid}", f"EventLog [{eid}] {desc} - {entry.get('payload', '')[:100]}", entry)

                elif tool_name == "analyze_powershell_logs":
                    eid = entry.get("event_id")
                    if entry.get("timestamp"):
                        self._add_event(entry["timestamp"], f"powershell_{eid}", f"PowerShell Event [{eid}] - {entry.get('script_block_text', '')[:100]}", entry)

                elif tool_name == "analyze_usn_journal":
                    file_name = entry.get("file_name") or "Unknown"
                    reason = entry.get("update_reasons") or "Unknown"
                    if entry.get("update_timestamp"):
                        self._add_event(entry["update_timestamp"], "usn_journal", f"USN Journal: {file_name} ({reason})", {"file": file_name, "reason": reason, "parent_path": entry.get("parent_path")})
        except Exception:
            pass

    def _add_event(self, ts_str: str, event_type: str, description: str, metadata: dict) -> None:
        dt = self._parse_timestamp(ts_str)
        if dt:
            self.events.append({
                "timestamp": dt.isoformat(),
                "raw_timestamp": ts_str,
                "event_type": event_type,
                "description": description,
                "metadata": metadata
            })

    def _parse_timestamp(self, ts_str: str) -> datetime | None:
        if not ts_str:
            return None
        ts_str = ts_str.strip()
        formats = [
            "%Y-%m-%d %H:%M:%S.%f %Z",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S %Z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
        ]

        ts_clean = ts_str.replace(" UTC", "").replace("Z", "")
        for fmt in formats:
            try:
                if "%Z" in fmt:
                    dt = datetime.strptime(ts_str, fmt)
                else:
                    dt = datetime.strptime(ts_clean, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})", ts_clean)
        if m:
            try:
                dt = datetime(
                    int(m.group(1)), int(m.group(2)), int(m.group(3)),
                    int(m.group(4)), int(m.group(5)), int(m.group(6)),
                    tzinfo=timezone.utc
                )
                return dt
            except ValueError:
                pass
        return None

    def analyze_consistency(self) -> float:
        """
        Analyzes the chronological events for contradictions.
        Returns consistency score between 0.0 and 1.0.
        """
        self.contradictions = []
        if len(self.events) < 2:
            return 1.0

        sorted_events = sorted(self.events, key=lambda x: x["timestamp"])
        file_lifecycle = {}

        for ev in sorted_events:
            meta = ev["metadata"]
            ts = ev["timestamp"]

            file_name = None
            if ev["event_type"] == "prefetch_execution":
                file_name = meta.get("executable")
            elif ev["event_type"] == "amcache_first_run":
                file_name = meta.get("file")
            elif ev["event_type"] == "shimcache_modified":
                file_name = os.path.basename(meta.get("path", ""))
            elif ev["event_type"] == "usn_journal":
                file_name = meta.get("file")

            if file_name:
                file_name = file_name.lower()
                if file_name not in file_lifecycle:
                    file_lifecycle[file_name] = {}

                if ev["event_type"] in ("prefetch_execution", "amcache_first_run"):
                    file_lifecycle[file_name]["executed"] = ts
                elif ev["event_type"] == "shimcache_modified":
                    file_lifecycle[file_name]["modified"] = ts
                elif ev["event_type"] == "usn_journal":
                    reason = meta.get("reason", "").upper()
                    if "FILE_CREATE" in reason:
                        file_lifecycle[file_name]["created"] = ts
                    elif "FILE_DELETE" in reason:
                        file_lifecycle[file_name]["deleted"] = ts

        for file_name, lifecycle in file_lifecycle.items():
            created = lifecycle.get("created")
            executed = lifecycle.get("executed")
            deleted = lifecycle.get("deleted")
            modified = lifecycle.get("modified")

            if executed and created and executed < created:
                self.contradictions.append(
                    f"Contradiction: File '{file_name}' executed at {executed} before creation at {created}."
                )
            if executed and deleted and executed > deleted:
                self.contradictions.append(
                    f"Anomaly: File '{file_name}' executed at {executed} after deletion at {deleted}."
                )
            if modified and created and modified < created:
                self.contradictions.append(
                    f"Contradiction: File '{file_name}' modified at {modified} before creation at {created}."
                )

        score = max(0.0, 1.0 - len(self.contradictions) * 0.20)
        return score

    def get_chronological_events(self) -> list[dict[str, Any]]:
        return sorted(self.events, key=lambda x: x["timestamp"])


# ---------------------------------------------------------------------------
# MITRE ATT&CK Mapping
# ---------------------------------------------------------------------------

class MitreAttackMapper:
    """
    Maps forensic evidence claims to MITRE ATT&CK tactics and techniques.
    """
    MAPPING_RULES = [
        # Initial Access
        {"keywords": ["phishing", "attachment", "email", "mail"], "tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1566", "technique_name": "Phishing"},
        {"keywords": ["vpn", "remote service", "remote access"], "tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1133", "technique_name": "External Remote Services"},
        {"keywords": ["valid account", "compromised credentials"], "tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1078", "technique_name": "Valid Accounts"},

        # Execution
        {"keywords": ["powershell", "cmd.exe", "wmic", "scripting", "command line"], "tactic_id": "TA0002", "tactic_name": "Execution", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"},
        {"keywords": ["user execution", "clicked", "opened file"], "tactic_id": "TA0002", "tactic_name": "Execution", "technique_id": "T1204", "technique_name": "User Execution"},
        {"keywords": ["wmi", "wmic process"], "tactic_id": "TA0002", "tactic_name": "Execution", "technique_id": "T1047", "technique_name": "Windows Management Instrumentation"},
        {"keywords": ["psexesvc", "psexec", "service execution"], "tactic_id": "TA0002", "tactic_name": "Execution", "technique_id": "T1569.002", "technique_name": "System Services: Service Execution"},
        {"keywords": ["powershell download", "downloadfile", "script block", "sysmon64.exe delivery"], "tactic_id": "TA0002", "tactic_name": "Execution", "technique_id": "T1059.001", "technique_name": "Command and Scripting Interpreter: PowerShell"},

        # Persistence
        {"keywords": ["run key", "startup folder", "registry run"], "tactic_id": "TA0003", "tactic_name": "Persistence", "technique_id": "T1547.001", "technique_name": "Registry Run Keys / Startup Folder"},
        {"keywords": ["scheduled task", "update_sysmon_rules", "schtasks"], "tactic_id": "TA0003", "tactic_name": "Persistence", "technique_id": "T1053.005", "technique_name": "Scheduled Task/Job: Scheduled Task"},
        {"keywords": ["service creation", "installed service", "system service"], "tactic_id": "TA0003", "tactic_name": "Persistence", "technique_id": "T1543", "technique_name": "Create or Modify System Process"},
        {"keywords": ["registered as a service", "windows service", "service registration"], "tactic_id": "TA0003", "tactic_name": "Persistence", "technique_id": "T1543.003", "technique_name": "Create or Modify System Process: Windows Service"},

        # Privilege Escalation
        {"keywords": ["uac bypass", "bypass uac", "elevation control"], "tactic_id": "TA0004", "tactic_name": "Privilege Escalation", "technique_id": "T1548", "technique_name": "Abuse Elevation Control Mechanism"},
        {"keywords": ["process injection", "remote thread", "inject"], "tactic_id": "TA0004", "tactic_name": "Privilege Escalation", "technique_id": "T1055", "technique_name": "Process Injection"},
        {"keywords": ["token manipulation", "4672", "special privilege"], "tactic_id": "TA0004", "tactic_name": "Privilege Escalation", "technique_id": "T1134", "technique_name": "Token Manipulation"},

        # Defense Evasion
        {"keywords": ["clear event", "wevtutil", "delete logs", "removal"], "tactic_id": "TA0005", "tactic_name": "Defense Evasion", "technique_id": "T1070", "technique_name": "Indicator Removal"},
        {"keywords": ["disable defender", "stop service", "impair defenses"], "tactic_id": "TA0005", "tactic_name": "Defense Evasion", "technique_id": "T1562", "technique_name": "Impair Defenses"},
        {"keywords": ["subvert trust", "trust controls"], "tactic_id": "TA0005", "tactic_name": "Defense Evasion", "technique_id": "T1553", "technique_name": "Subvert Trust Controls"},

        # Credential Access
        {"keywords": ["pwdump", "pwdumpx", "credential dump", "sam dump", "lsass"], "tactic_id": "TA0006", "tactic_name": "Credential Access", "technique_id": "T1003", "technique_name": "OS Credential Dumping"},

        # Discovery
        {"keywords": ["systeminfo", "service discovery"], "tactic_id": "TA0007", "tactic_name": "Discovery", "technique_id": "T1007", "technique_name": "System Service Discovery"},
        {"keywords": ["net user", "account discovery"], "tactic_id": "TA0007", "tactic_name": "Discovery", "technique_id": "T1087", "technique_name": "Account Discovery"},
        {"keywords": ["find file", "directory discovery", "search"], "tactic_id": "TA0007", "tactic_name": "Discovery", "technique_id": "T1083", "technique_name": "File and Directory Discovery"},

        # Lateral Movement
        {"keywords": ["rdp", "remote desktop"], "tactic_id": "TA0008", "tactic_name": "Lateral Movement", "technique_id": "T1021", "technique_name": "Remote Services"},
        {"keywords": ["psexec", "deployment tools"], "tactic_id": "TA0008", "tactic_name": "Lateral Movement", "technique_id": "T1072", "technique_name": "Software Deployment Tools"},
        {"keywords": ["pass the hash", "pth", "alternate authentication"], "tactic_id": "TA0008", "tactic_name": "Lateral Movement", "technique_id": "T1550", "technique_name": "Use Alternate Authentication Material"},

        # Collection
        {"keywords": ["zip", "archive", "tar", "rar"], "tactic_id": "TA0009", "tactic_name": "Collection", "technique_id": "T1560", "technique_name": "Archive Collected Data"},
        {"keywords": ["mail collection", "pst", "email collection"], "tactic_id": "TA0009", "tactic_name": "Collection", "technique_id": "T1114", "technique_name": "Email Collection"},
        {"keywords": ["local system", "database dump"], "tactic_id": "TA0009", "tactic_name": "Collection", "technique_id": "T1005", "technique_name": "Data from Local System"},

        # Exfiltration
        {"keywords": ["ftp", "sftp", "alternative protocol"], "tactic_id": "TA0010", "tactic_name": "Exfiltration", "technique_id": "T1048", "technique_name": "Exfiltration Over Alternative Protocol"},
        {"keywords": ["upload", "web service", "mega.nz"], "tactic_id": "TA0010", "tactic_name": "Exfiltration", "technique_id": "T1567", "technique_name": "Exfiltration Over Web Service"},
    ]

    @classmethod
    def map_finding(cls, claim: str, sources: list[str], supporting_observations: list[str] | None = None) -> list[dict[str, Any]]:
        mappings = []
        if not sources and not supporting_observations and not claim:
            return []

        claim_lower = claim.lower() if claim else ""
        sources_lower = [s.lower() for s in sources] if sources else []
        obs_lower = [obs.lower() for obs in supporting_observations] if supporting_observations else []

        # Combine all finding context into a single string for mapping
        full_context = claim_lower + " " + " ".join(sources_lower) + " " + " ".join(obs_lower)

        for rule in cls.MAPPING_RULES:
            # Check evidence-based constraint for lateral movement:
            # do not map lateral movement unless Logon Type 3/10 or network/Sysmon connection evidence supports it
            if rule["tactic_id"] == "TA0008":
                has_logon = any(ts in full_context for ts in ["logon type 3", "logon type 10", "type 3", "type 10"])
                has_network = any(n in full_context for n in ["tshark", "pcap", "network connection"]) or "run_tshark_summary" in sources_lower or "analyze_network_connections" in sources_lower
                has_sysmon_net = "analyze_sysmon" in sources_lower and any("network" in obs for obs in obs_lower)

                if not (has_logon or has_network or has_sysmon_net):
                    continue

            matched_kw = [kw for kw in rule["keywords"] if kw in full_context]
            if matched_kw:
                mappings.append({
                    "tactic_id": rule["tactic_id"],
                    "tactic_name": rule["tactic_name"],
                    "technique_id": rule["technique_id"],
                    "technique_name": rule["technique_name"],
                    "matched_keywords": matched_kw
                })
        return mappings


def get_timeline_evidence_for_finding(eo: EvidenceObject, timeline: ForensicTimeline) -> list[dict[str, Any]]:
    """
    Extracts chronological events related to a specific finding based on keywords (files, users).
    """
    words = re.findall(r"[\w.-]+\.\w{3}", eo.claim + " " + " ".join(eo.supporting_observations))
    words.extend(re.findall(r"\b(?:user|admin|administrator|sansforensics|guest|system)\b", eo.claim.lower()))

    related_events = []
    seen_desc = set()
    for ev in timeline.get_chronological_events():
        desc_lower = ev["description"].lower()
        for w in words:
            if w.lower() in desc_lower and ev["description"] not in seen_desc:
                related_events.append(ev)
                seen_desc.add(ev["description"])
                break
    return related_events[:5]


def _parse_json_blocks_with_marker(text: str, marker: str, required_key: str) -> list[dict[str, Any]]:
    results = []
    idx = 0
    text_lower = text.lower()
    marker_lower = marker.lower()
    while True:
        pos = text_lower.find(marker_lower, idx)
        if pos == -1:
            break
        # Find the next '{' after the marker
        start_idx = text.find("{", pos + len(marker))
        if start_idx == -1:
            idx = pos + len(marker)
            continue
        try:
            decoder = json.JSONDecoder()
            obj, end = decoder.raw_decode(text[start_idx:])
            if isinstance(obj, dict) and required_key in obj:
                results.append(obj)
            idx = start_idx + end
        except (json.JSONDecodeError, ValueError):
            idx = start_idx + 1
    return results


def _parse_investigation_plans(text: str) -> list[dict[str, Any]]:
    """
    Parse structured investigation plans from model output text.
    Looks for investigation_plan blocks containing JSON (fenced or unfenced).
    Returns a list of parsed plan dictionaries.
    """
    plans = _parse_json_blocks_with_marker(text, "investigation_plan", "hypothesis")
    if plans:
        return plans

    plans = []
    pattern = r'```investigation_plan\s*\n(.*?)\n```'
    for match in re.finditer(pattern, text, re.DOTALL):
        try:
            raw = match.group(1).strip()
            plan_data = json.loads(raw)
            if isinstance(plan_data, dict) and "hypothesis" in plan_data:
                plans.append(plan_data)
        except (json.JSONDecodeError, ValueError):
            continue
    return plans


# ---------------------------------------------------------------------------
# Evidence Claim Parsing Helpers
# ---------------------------------------------------------------------------

def _parse_evidence_claims(text: str) -> list[dict[str, str]]:
    """
    Parse structured evidence claims from model output text.
    Looks for evidence_claim blocks containing JSON (fenced or unfenced).
    Returns a list of parsed claim dictionaries.
    """
    claims = _parse_json_blocks_with_marker(text, "evidence_claim", "claim")
    if claims:
        return [{str(k): str(v) for k, v in c.items()} for c in claims]

    claims = []
    pattern = r'```evidence_claim\s*\n(.*?)\n```'
    for match in re.finditer(pattern, text, re.DOTALL):
        try:
            raw = match.group(1).strip()
            claim_data = json.loads(raw)
            if isinstance(claim_data, dict) and "claim" in claim_data:
                claims.append({str(k): str(v) for k, v in claim_data.items()})
        except (json.JSONDecodeError, ValueError):
            continue
    return claims


def _parse_verification_result(text: str) -> dict[str, str] | None:
    """
    Parse a verification result block from model output.
    Looks for verification_result blocks containing JSON (fenced or unfenced).
    Returns the parsed result dictionary, or None if not found.
    """
    results = _parse_json_blocks_with_marker(text, "verification_result", "status")
    if results:
        return {str(k): str(v) for k, v in results[0].items()}

    pattern = r'```verification_result\s*\n(.*?)\n```'
    match = re.search(pattern, text, re.DOTALL)
    if match:
        try:
            raw = match.group(1).strip()
            result = json.loads(raw)
            if isinstance(result, dict) and "status" in result:
                return {str(k): str(v) for k, v in result.items()}
        except (json.JSONDecodeError, ValueError):
            pass
    return None


# ---------------------------------------------------------------------------
# Correlation Report Generator
# ---------------------------------------------------------------------------

def _print_correlation_report(
    correlator: EvidenceCorrelator,
    timeline: ForensicTimeline,
    logger: "AuditLogger",
) -> None:
    """
    Generate and print an upgraded structured forensic correlation report.
    Each finding shows: Claim, Confidence, Supporting Evidence,
    Contradictions, Verification Actions, Timeline Evidence, ATT&CK Mapping, and Final Assessment.
    Also logs the report summary to the audit log.
    """
    if getattr(logger, "is_tool_validation", False):
        executed_tools = getattr(logger, "executed_tools", [])

        tools_success = []
        tools_no_results = []
        tools_error = []
        for t in executed_tools:
            if t["status"] == "success" and (t["total_entries"] is None or t["total_entries"] > 0):
                tools_success.append(t)
            elif t["status"] == "no_results" or (t["status"] == "success" and t["total_entries"] == 0):
                tools_no_results.append(t)
            else:
                tools_error.append(t)

        print(f"\n{'='*80}")
        print(f"  TOOL VALIDATION REPORT")
        print(f"{'='*80}")
        print("  EXECUTIVE SUMMARY")
        print("  -----------------")
        print(f"    Total Tools Run: {len(executed_tools)}")
        print(f"    Successful     : {len(tools_success)}")
        print(f"    No Results     : {len(tools_no_results)}")
        print(f"    Errors/Failed  : {len(tools_error)}")
        print()

        print("  DETAILED TOOL RESULTS")
        print("  ---------------------")
        if tools_success:
            print("    Successful tools (returned entries):")
            for t in tools_success:
                entry_str = f" ({t['total_entries']} entries)" if t["total_entries"] is not None else ""
                print(f"      - {t['tool_name']}{entry_str}")
        if tools_no_results:
            print("    Tools with no results:")
            for t in tools_no_results:
                print(f"      - {t['tool_name']}")
        if tools_error:
            print("    Tools with errors:")
            for t in tools_error:
                print(f"      - {t['tool_name']}")
        print(f"{'-'*80}")
        print("  Tool validation completed successfully.")
        print(f"{'='*80}\n")

        report_data = {
            "is_tool_validation": True,
            "total_tools_run": len(executed_tools),
            "successful_tools": [t["tool_name"] for t in tools_success],
            "no_results_tools": [t["tool_name"] for t in tools_no_results],
            "error_tools": [t["tool_name"] for t in tools_error]
        }
        logger.log_report_generated(report_data)
        return

    all_evidence = correlator.get_all()
    summary = correlator.get_summary()

    # Determine confidence distribution
    conf_dist = summary.get("by_confidence", {"high": 0, "medium": 0, "low": 0})

    # Gather MITRE ATT&CK mappings and counts
    attack_counts = {}
    for eo in all_evidence:
        for mapping in getattr(eo, "attack_mappings", []):
            key = (mapping["tactic_name"], mapping["technique_name"], mapping["technique_id"])
            attack_counts[key] = attack_counts.get(key, 0) + 1

    # Gather evidence sources
    sources_used = set()
    for eo in all_evidence:
        sources_used.update(eo.evidence_sources)

    print(f"\n{'='*80}")
    print(f"  UPGRADED FORENSIC CORRELATION & ATT&CK REPORT")
    print(f"{'='*80}")

    print("  EXECUTIVE SUMMARY")
    print("  -----------------")
    print(f"    Total Findings : {summary['total_findings']}")
    print(f"    Verified       : {summary['by_status']['verified']}")
    print(f"    Refuted        : {summary['by_status']['refuted']}")
    print(f"    Inconclusive   : {summary['by_status']['inconclusive']}")
    print(f"    Unverified     : {summary['by_status']['hypothesis']}")
    print()
    print("  CONFIDENCE DISTRIBUTION")
    print("  -----------------------")
    print(f"    High Confidence: {conf_dist.get('high', 0)}")
    print(f"    Med Confidence : {conf_dist.get('medium', 0)}")
    print(f"    Low Confidence : {conf_dist.get('low', 0)}")
    print()

    print("  MITRE ATT&CK SUMMARY")
    print("  --------------------")
    if not attack_counts:
        print("    No MITRE ATT&CK techniques mapped to forensic findings.")
    else:
        print(f"    {'Tactic':<25} | {'Technique':<35} | {'ID':<10} | {'Count':<5}")
        print(f"    {'-'*25}-|-{'-'*35}-|-{'-'*10}-|-{'-'*5}")
        for (tactic, tech, tech_id), count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"    {tactic[:25]:<25} | {tech[:35]:<35} | {tech_id:<10} | {count:<5}")
    print()

    print("  EVIDENCE SOURCES USED")
    print("  ---------------------")
    if not getattr(logger, "executed_tools", []) and not sources_used:
        print("    No remote SIFT workstation evidence sources utilized.")
    else:
        if sources_used:
            print("    Evidence sources linked to findings:")
            for src in sorted(sources_used):
                print(f"      * {src}")
            print()

        executed_tools = getattr(logger, "executed_tools", [])
        if executed_tools:
            print("    MCP Tools Executed:")
            tools_success = []
            tools_no_results = []
            tools_error = []
            for t in executed_tools:
                if t["status"] == "success" and (t["total_entries"] is None or t["total_entries"] > 0):
                    tools_success.append(t)
                elif t["status"] == "no_results" or (t["status"] == "success" and t["total_entries"] == 0):
                    tools_no_results.append(t)
                else:
                    tools_error.append(t)

            print(f"      * Total Executed: {len(executed_tools)}")
            if tools_success:
                print("      * Tools with entries:")
                for t in tools_success:
                    entry_str = f" ({t['total_entries']} entries)" if t["total_entries"] is not None else ""
                    print(f"        - {t['tool_name']}{entry_str}")
            if tools_no_results:
                print("      * Tools with no results:")
                for t in tools_no_results:
                    print(f"        - {t['tool_name']}")
            if tools_error:
                print("      * Tools with errors:")
                for t in tools_error:
                    print(f"        - {t['tool_name']}")
    print()

    print("  ATTACK NARRATIVE")
    print("  ----------------")
    sorted_ev = timeline.get_chronological_events()
    if not sorted_ev:
        print("    No chronological timeline events reconstructed from SIFT evidence.")
    else:
        print("    Reconstructed timeline of activities:")
        for idx, ev in enumerate(sorted_ev[:15], start=1):
            print(f"      {idx:02d}. [{ev['timestamp']}] - {ev['description']}")
        if len(sorted_ev) > 15:
            print(f"      ... and {len(sorted_ev) - 15} more timeline events.")
    print(f"{'-'*80}")

    if not all_evidence:
        print("  No structured evidence claims were generated.")
        print("  (The model may not have emitted evidence_claim blocks.)")
        print(f"{'='*80}\n")
        logger.log_report_generated(summary)
        return

    print("  DETAILED FINDINGS")
    print("  -----------------")
    dfir_validator = DFIRValidator()

    for idx, eo in enumerate(all_evidence, start=1):
        confidence_pct = f"{eo.confidence_score:.0%}"
        status_icon = {
            "verified": "[OK]",
            "refuted": "[FAIL]",
            "inconclusive": "?",
            "hypothesis": "o",
        }.get(eo.status, ".")

        print(f"\n  [{idx:02d}] {status_icon} {eo.claim}")
        print(f"       Finding ID  : {eo.finding_id}")
        if eo.parent_hypothesis_id:
            print(f"       Parent Hypo : {eo.parent_hypothesis_id}")
        print(f"       Hypothesis  : {eo.hypothesis_id}")
        print(f"       Confidence  : {confidence_pct} ({eo.confidence_label})")
        print(f"       Status      : {eo.status.upper()}")

        print(f"       +- Supporting Evidence ({len(eo.supporting_observations)}):")
        if eo.supporting_observations:
            for obs in eo.supporting_observations[:5]:
                print(f"       |  * {obs[:100]}")
        else:
            print(f"       |  (none)")

        print(f"       +- Evidence Sources ({len(eo.evidence_sources)}):")
        if eo.evidence_sources:
            print(f"       |  {', '.join(eo.evidence_sources)}")
        else:
            print(f"       |  (none)")

        print(f"       +- Contradictions ({len(eo.contradictory_observations)}):")
        if eo.contradictory_observations:
            for obs in eo.contradictory_observations[:3]:
                print(f"       |  [WARNING] {obs[:100]}")
        else:
            print(f"       |  None")

        print(f"       +- Evidence Gaps ({len(getattr(eo, 'evidence_gaps', []))}):")
        if getattr(eo, 'evidence_gaps', None):
            for gap in eo.evidence_gaps[:3]:
                print(f"       |  [GAP] {gap[:100]}")
        else:
            print(f"       |  None")

        print(f"       +- Verification Actions ({len(eo.verification_actions)}):")
        if eo.verification_actions:
            for act in eo.verification_actions[:5]:
                print(f"       |  -> {act[:100]}")
        else:
            print(f"       |  (no verification performed)")

        # Timeline Evidence
        related_timeline = get_timeline_evidence_for_finding(eo, timeline)
        print(f"       +- Timeline Evidence ({len(related_timeline)}):")
        if related_timeline:
            for ev in related_timeline:
                print(f"       |  [{ev['timestamp']}] {ev['description'][:100]}")
        else:
            print(f"       |  (no related timeline events identified)")

        # MITRE ATT&CK Mapping
        print(f"       +- MITRE ATT&CK Mapping ({len(getattr(eo, 'attack_mappings', []))}):")
        if getattr(eo, "attack_mappings", None):
            for mapping in eo.attack_mappings:
                print(f"       |  * Tactic: {mapping['tactic_name']} ({mapping['tactic_id']}), Technique: {mapping['technique_name']} ({mapping['technique_id']})")
        else:
            print(f"       |  (none)")

        # DFIR validation warnings
        dfir_warnings = dfir_validator.validate(eo)
        if dfir_warnings:
            print(f"       +- DFIR Validation Warnings ({len(dfir_warnings)}):")
            for w in dfir_warnings:
                print(f"       |  [{w['severity']}] {w['rule']}: {w['message'][:90]}")

        # Final assessment
        if eo.status == "verified":
            assessment = f"{eo.confidence_label.title()}-confidence evidence ({confidence_pct}). Finding corroborated."
        elif eo.status == "refuted":
            assessment = f"Finding refuted. Contradictory evidence outweighs support."
        elif eo.status == "inconclusive":
            assessment = f"Insufficient evidence to confirm or deny ({confidence_pct})."
        else:
            assessment = f"Unverified hypothesis at {confidence_pct} confidence."

        print(f"       +- Final Assessment: {assessment}")

    print(f"\n  {'='*76}\n")

    # Build report data for audit log
    report_data = {
        **summary,
        "findings": [eo.to_dict() for eo in all_evidence],
        "timeline_events_count": len(sorted_ev),
        "attack_mappings_count": len(attack_counts),
    }
    logger.log_report_generated(report_data)


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """
    Writes structured JSONL entries for every significant agent event.
    Each entry includes a session ID, wall-clock timestamp, event type,
    and all relevant payload fields (tool name, args, result, token usage).

    Enhanced with evidence correlation, confidence tracking, and
    verification traceability.
    """

    def __init__(self, log_path: Path, session_id: str) -> None:
        self.log_path = log_path
        self.session_id = session_id
        self._file = log_path.open("a", encoding="utf-8")
        self.executed_tools = []

    def _write(self, event_type: str, payload: dict[str, Any]) -> None:
        entry = {
            "session_id": self.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            **payload,
        }
        self._file.write(json.dumps(entry) + "\n")
        self._file.flush()

    def log_session_start(self, task: str, max_iterations: int, model: str) -> None:
        self._write("session_start", {
            "task": task,
            "max_iterations": max_iterations,
            "model": model,
            "remote_host": REMOTE_HOST,
            "max_verification_iterations": MAX_VERIFICATION_ITERATIONS,
        })

    def log_iteration(self, iteration: int) -> None:
        self._write("iteration_begin", {"iteration": iteration})

    def log_tool_call(
        self,
        iteration: int,
        tool_name: str,
        tool_use_id: str,
        arguments: dict[str, Any],
        hypothesis_id: str = "",
    ) -> None:
        payload: dict[str, Any] = {
            "iteration": iteration,
            "tool_name": tool_name,
            "tool_use_id": tool_use_id,
            "arguments": arguments,
        }
        if hypothesis_id:
            payload["hypothesis_id"] = hypothesis_id
        self._write("tool_call", payload)

    def log_tool_result(
        self,
        iteration: int,
        tool_name: str,
        tool_use_id: str,
        result: Any,
        elapsed_ms: float,
        hypothesis_id: str = "",
        confidence_before: float | None = None,
        confidence_after: float | None = None,
    ) -> None:
        payload: dict[str, Any] = {
            "iteration": iteration,
            "tool_name": tool_name,
            "tool_use_id": tool_use_id,
            "result_preview": str(result)[:500],
            "elapsed_ms": round(elapsed_ms, 2),
        }
        if hypothesis_id:
            payload["hypothesis_id"] = hypothesis_id
        if confidence_before is not None:
            payload["confidence_before"] = round(confidence_before, 2)
        if confidence_after is not None:
            payload["confidence_after"] = round(confidence_after, 2)
        self._write("tool_result", payload)

        # Extract raw text from result, handling list or other types
        raw_text = ""
        if isinstance(result, str):
            raw_text = result
        elif isinstance(result, list):
            parts = []
            for part in result:
                if isinstance(part, str):
                    parts.append(part)
                elif hasattr(part, "text") and part.text:
                    parts.append(part.text)
                elif isinstance(part, dict) and "text" in part:
                    parts.append(part["text"])
            raw_text = "".join(parts)
        else:
            raw_text = str(result)

        status = "success"
        entries = None
        try:
            data = json.loads(raw_text)
            if isinstance(data, dict):
                # Retrieve status first. success, timeout, and no_results are NOT errors
                status = data.get("status", "success")
                entries = data.get("total_entries", None)
                if entries is None and "entries" in data and isinstance(data["entries"], list):
                    entries = len(data["entries"])

                # Check for "error" key, but status = success/timeout/no_results overrides error classification
                if "error" in data and status not in ("success", "timeout", "no_results"):
                    status = "error"
        except Exception:
            if raw_text.startswith("Tool error:") or "exception" in raw_text.lower():
                status = "error"
            else:
                status = "success"

        self.executed_tools.append({
            "tool_name": tool_name,
            "status": status,
            "total_entries": entries
        })

    def log_token_usage(
        self,
        iteration: int,
        input_tokens: int,
        output_tokens: int,
        cache_read: int = 0,
        cache_write: int = 0,
    ) -> None:
        self._write("token_usage", {
            "iteration": iteration,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_tokens": cache_read,
            "cache_write_tokens": cache_write,
            "total_tokens": input_tokens + output_tokens,
        })

    def log_consistency_check(
        self,
        iteration: int,
        findings: list[str],
        issues: list[str],
        passed: bool,
    ) -> None:
        self._write("consistency_check", {
            "iteration": iteration,
            "findings_count": len(findings),
            "issues": issues,
            "passed": passed,
        })

    def log_agent_decision(self, iteration: int, stop_reason: str, message: str = "") -> None:
        self._write("agent_decision", {
            "iteration": iteration,
            "stop_reason": stop_reason,
            "message": message[:300] if message else "",
        })

    def log_session_end(
        self,
        iterations_used: int,
        total_input_tokens: int,
        total_output_tokens: int,
        outcome: str,
    ) -> None:
        self._write("session_end", {
            "iterations_used": iterations_used,
            "total_input_tokens": total_input_tokens,
            "total_output_tokens": total_output_tokens,
            "total_tokens": total_input_tokens + total_output_tokens,
            "outcome": outcome,
        })

    # --- Enhanced logging for evidence correlation ---

    def log_investigation_plan(self, plan: dict[str, Any]) -> None:
        """Log when a new investigation plan is generated."""
        self._write("investigation_plan", plan)

    def log_evidence_created(self, evidence: "EvidenceObject") -> None:
        """Log when a new evidence object is created."""
        self._write("evidence_created", {
            "finding_id": evidence.finding_id,
            "hypothesis_id": evidence.hypothesis_id,
            "claim": evidence.claim[:200],
            "initial_confidence": round(evidence.confidence_score, 2),
            "confidence_label": evidence.confidence_label,
            "source_count": len(evidence.evidence_sources),
            "sources": evidence.evidence_sources,
        })

    def log_confidence_update(
        self,
        finding_id: str,
        old_score: float,
        new_score: float,
        reason: str,
    ) -> None:
        """Log every confidence score change with reason."""
        self._write("confidence_update", {
            "finding_id": finding_id,
            "confidence_before": round(old_score, 2),
            "confidence_after": round(new_score, 2),
            "delta": round(new_score - old_score, 2),
            "reason": reason[:200],
        })

    def log_verification_step(
        self,
        finding_id: str,
        hypothesis_id: str,
        action: str,
        result: str,
        confidence_before: float,
        confidence_after: float,
    ) -> None:
        """Log each verification action with full before/after state."""
        self._write("verification_step", {
            "finding_id": finding_id,
            "hypothesis_id": hypothesis_id,
            "action": action[:200],
            "verification_result": result,
            "confidence_before": round(confidence_before, 2),
            "confidence_after": round(confidence_after, 2),
        })

    def log_dfir_validation(
        self,
        finding_id: str,
        rules_checked: list[str],
        warnings: list[dict[str, str]],
    ) -> None:
        """Log DFIR validation rule outcomes."""
        self._write("dfir_validation", {
            "finding_id": finding_id,
            "rules_checked": rules_checked,
            "warning_count": len(warnings),
            "warnings": warnings,
        })

    def log_report_generated(self, summary: dict[str, Any]) -> None:
        """Log the final correlation report summary."""
        self._write("report_generated", summary)

    def close(self) -> None:
        self._file.close()


# ---------------------------------------------------------------------------
# Logical Consistency Checker (Enhanced with Evidence Correlation)
# ---------------------------------------------------------------------------

def check_logical_consistency(
    findings: list[str],
    correlator: "EvidenceCorrelator | None" = None,
) -> tuple[bool, list[str]]:
    """
    Evaluates a list of forensic finding strings for logical contradictions
    and common integrity issues.

    When an EvidenceCorrelator is provided, also checks structured evidence
    objects for DFIR validation warnings.

    Returns:
        (passed: bool, issues: list[str])
            passed=True  -> no issues detected
            passed=False -> issues list contains human-readable descriptions
    """
    issues: list[str] = []

    if not findings and (correlator is None or not correlator.get_all()):
        return True, []

    findings_lower = [f.lower() for f in findings]

    # Rule 1: Hash mismatch contradiction
    hash_ok = any("hash match" in f or "integrity verified" in f for f in findings_lower)
    hash_fail = any("hash mismatch" in f or "integrity fail" in f for f in findings_lower)
    if hash_ok and hash_fail:
        issues.append(
            "CONTRADICTION: Findings simultaneously claim hash match AND hash mismatch. "
            "Re-verify image integrity before proceeding."
        )

    # Rule 2: Mount state contradiction
    mounted = any("mounted" in f and "read-only" in f for f in findings_lower)
    not_mounted = any("not mounted" in f or "unmounted" in f for f in findings_lower)
    if mounted and not_mounted:
        issues.append(
            "CONTRADICTION: Image reported as both mounted (read-only) and not mounted. "
            "Check ewfmount status on SIFT VM."
        )

    # Rule 3: Evidence path must be consistent across findings
    paths_mentioned = set()
    for f in findings:
        for match in re.findall(r"/[\w/._-]{5,}", f):
            paths_mentioned.add(match)
    if len(paths_mentioned) > 3:
        issues.append(
            f"WARNING: Multiple distinct paths referenced ({', '.join(list(paths_mentioned)[:5])}). "
            "Confirm all paths resolve to the same evidence mount."
        )

    # Rule 4: Timestamp plausibility (evidence older than 2000 shouldn't appear as 'recent')
    recent_and_old = (
        any("recent" in f for f in findings_lower)
        and any(("199" in f) or ("198" in f) for f in findings_lower)
    )
    if recent_and_old:
        issues.append(
            "WARNING: Findings describe old filesystem timestamps (pre-2000) as 'recent'. "
            "Review timeline logic -- possible timezone or epoch parsing error."
        )

    # Rule 5: Write activity on a read-only mount
    write_on_readonly = (
        any("read-only" in f for f in findings_lower)
        and any(("file written" in f or "created file" in f or "deleted" in f) for f in findings_lower)
    )
    if write_on_readonly:
        issues.append(
            "CRITICAL: Write activity reported on a mount declared read-only. "
            "This may indicate evidence contamination -- halt and review immediately."
        )

    # Rule 6 (NEW): Structured evidence validation via DFIR rules
    if correlator:
        validator = DFIRValidator()
        for eo in correlator.get_all():
            if eo.status == "refuted":
                continue
            dfir_warnings = validator.validate(eo)
            for w in dfir_warnings:
                if w["severity"] in ("IMPORTANT", "WARNING"):
                    issues.append(
                        f"DFIR [{w['rule']}]: {w['message']}"
                    )

    passed = len(issues) == 0
    return passed, issues


# ---------------------------------------------------------------------------
# Diagnostic Helpers -- Exception & Subprocess Inspection
# ---------------------------------------------------------------------------

def _format_exception_tree(exc: BaseException, indent: int = 0) -> str:
    """
    Recursively unpack ExceptionGroup / BaseExceptionGroup and format
    every sub-exception with its type, message, and full traceback.
    Produces a visual tree of the entire exception chain.
    """
    lines: list[str] = []
    prefix = "  " * indent
    marker = "+-- " if indent else ""

    # Exception header
    exc_type = f"{type(exc).__module__}.{type(exc).__qualname__}"
    lines.append(f"{prefix}{marker}[{exc_type}] {exc}")

    # Full traceback for this specific exception
    if exc.__traceback__:
        import traceback as _tb
        tb_lines = _tb.format_tb(exc.__traceback__)
        for tb_line in tb_lines:
            for sub in tb_line.rstrip().splitlines():
                lines.append(f"{prefix}    {sub}")

    # Recurse into ExceptionGroup sub-exceptions
    if isinstance(exc, BaseExceptionGroup):
        lines.append(f"{prefix}    +== {len(exc.exceptions)} sub-exception(s) ==============+")
        for i, sub_exc in enumerate(exc.exceptions, 1):
            lines.append(f"{prefix}    | [{i}/{len(exc.exceptions)}]")
            lines.append(_format_exception_tree(sub_exc, indent + 2))
        lines.append(f"{prefix}    +{'=' * 40}+")

    # Explicit cause: raise X from Y
    if exc.__cause__:
        lines.append(f"{prefix}    +- Caused by (explicit __cause__):")
        lines.append(_format_exception_tree(exc.__cause__, indent + 1))
    # Implicit context: during handling of X, Y occurred
    elif exc.__context__ and not exc.__suppress_context__:
        lines.append(f"{prefix}    +- During handling, another exception occurred (__context__):")
        lines.append(_format_exception_tree(exc.__context__, indent + 1))

    return "\n".join(lines)


def _run_raw_ssh_diagnostic() -> None:
    """
    Spawn the SSH->MCP command directly via subprocess, send a minimal
    JSON-RPC initialize request, and capture raw stdout/stderr.

    This bypasses the MCP SDK entirely to reveal what the remote process
    actually emits on its stdio channels -- including any stdout pollution
    that would corrupt JSON-RPC framing.
    """
    import subprocess as sp

    print(f"\n{'-'*60}")
    print(f"  Raw SSH Subprocess Diagnostic")
    print(f"{'-'*60}")
    print(f"  Command: {' '.join(SSH_FLAGS)}")

    # Minimal MCP initialize request (JSON-RPC 2.0)
    init_request = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "diagnostic", "version": "0.1.0"}
        }
    })
    payload = (init_request + "\n").encode("utf-8")

    print(f"  Sending {len(payload)} bytes to stdin (initialize request)")
    print(f"  Payload: {init_request[:120]}...")

    try:
        proc = sp.Popen(
            SSH_FLAGS,
            stdin=sp.PIPE,
            stdout=sp.PIPE,
            stderr=sp.PIPE,
        )
        stdout_bytes, stderr_bytes = proc.communicate(input=payload, timeout=15)

        print(f"\n  Exit code: {proc.returncode}")

        if stdout_bytes:
            decoded = stdout_bytes.decode("utf-8", errors="replace")
            print(f"\n  stdout ({len(stdout_bytes)} bytes):")
            for line in decoded.splitlines()[:40]:
                print(f"    | {line}")
        else:
            print(f"\n  stdout: (empty -- server returned nothing on stdout)")

        if stderr_bytes:
            decoded = stderr_bytes.decode("utf-8", errors="replace")
            print(f"\n  stderr ({len(stderr_bytes)} bytes):")
            for line in decoded.splitlines()[:40]:
                print(f"    | {line}")
        else:
            print(f"\n  stderr: (empty)")

    except sp.TimeoutExpired:
        proc.kill()
        stdout_bytes, stderr_bytes = proc.communicate()
        print(f"\n  (process killed after 15s timeout -- server may be blocking on more input)")
        if stdout_bytes:
            print(f"  stdout ({len(stdout_bytes)} bytes):")
            for line in stdout_bytes.decode("utf-8", errors="replace").splitlines()[:40]:
                print(f"    | {line}")
        if stderr_bytes:
            print(f"  stderr ({len(stderr_bytes)} bytes):")
            for line in stderr_bytes.decode("utf-8", errors="replace").splitlines()[:40]:
                print(f"    | {line}")
    except Exception as diag_exc:
        print(f"\n  Diagnostic subprocess failed: {diag_exc}")

    print(f"{'-'*60}\n")


# ---------------------------------------------------------------------------
# Gemini SDK Helpers
# ---------------------------------------------------------------------------

def _get_gemini_client() -> genai.Client:
    """
    Create a Gemini client using the GEMINI_API_KEY environment variable.
    Raises a clear error if the key is missing.
    """
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY environment variable is not set.\n"
            "Set it in your .env file or export it in your shell:\n"
            "  export GEMINI_API_KEY='your-key-here'"
        )
    return genai.Client(api_key=api_key)


def _mcp_tools_to_gemini(mcp_tools: list) -> list[types.Tool]:
    """
    Convert MCP tool schemas (JSON Schema format) into Gemini
    FunctionDeclaration objects wrapped in a Tool list.
    """
    declarations = []
    for t in mcp_tools:
        schema = getattr(t, "inputSchema", None) or {}
        # Extract properties and required fields from the JSON schema
        parameters = None
        if schema.get("properties"):
            parameters = {
                "type": "OBJECT",
                "properties": {},
                "required": schema.get("required", []),
            }
            for param_name, param_def in schema["properties"].items():
                # Map JSON Schema types to Gemini schema types
                json_type = param_def.get("type", "string").upper()
                type_map = {
                    "STRING": "STRING",
                    "INTEGER": "INTEGER",
                    "NUMBER": "NUMBER",
                    "BOOLEAN": "BOOLEAN",
                    "ARRAY": "ARRAY",
                    "OBJECT": "OBJECT",
                }
                gemini_type = type_map.get(json_type, "STRING")
                prop = {"type": gemini_type}
                if "description" in param_def:
                    prop["description"] = param_def["description"]
                parameters["properties"][param_name] = prop

        decl = types.FunctionDeclaration(
            name=t.name,
            description=t.description or "",
            parameters=parameters,
        )
        declarations.append(decl)

    return [types.Tool(function_declarations=declarations)]


# ---------------------------------------------------------------------------
# Core Agent Loop (Enhanced with Evidence Correlation & Self-Correction)
# ---------------------------------------------------------------------------

async def run_agent(
    task: str,
    max_iterations: int,
    logger: AuditLogger,
    dry_run: bool = False,
    max_verification_iterations: int = MAX_VERIFICATION_ITERATIONS,
) -> None:
    """
    Main agentic loop. Connects to the remote SIFT MCP server via SSH stdio
    transport, discovers available tools, then drives a Gemini model in a
    tool-use loop until the model signals completion or max_iterations is hit.

    Enhanced with:
        - Evidence correlation engine (EvidenceCorrelator)
        - Confidence scoring with multi-source analysis
        - Self-correction via bounded verification stage
        - DFIR knowledge-driven validation
        - Structured correlation report generation
    """

    gemini_client = _get_gemini_client()

    task_lower = task.lower()
    is_tool_validation = any(phrase in task_lower for phrase in ["test the new mcp", "test fixed registry", "for each tool, report", "test mcp tools", "test tool"])
    logger.is_tool_validation = is_tool_validation

    server_params = StdioServerParameters(
        command=SSH_FLAGS[0],
        args=SSH_FLAGS[1:],
        env=dict(os.environ),
    )

    print(f"\n{'='*60}")
    print(f"  TriageForce Agent -- Session {logger.session_id[:8]}")
    print(f"  Task      : {task}")
    print(f"  Max iters : {max_iterations}")
    print(f"  Verify cap: {max_verification_iterations} per finding")
    print(f"  Model     : {GEMINI_MODEL}")
    print(f"  Provider  : Google Gemini")
    print(f"  Remote    : {REMOTE_HOST}")
    print(f"  Dry-run   : {dry_run}")
    print(f"  Audit log : {AUDIT_LOG_PATH}")
    print(f"{'='*60}\n")

    if dry_run:
        print("[DRY-RUN] Skipping SSH connection. Tool discovery and agent loop will not run.")
        logger.log_session_end(0, 0, 0, "dry_run_skipped")
        return

    # --- Initialize evidence correlation engine ---
    correlator = EvidenceCorrelator()
    dfir_validator = DFIRValidator()
    timeline = ForensicTimeline()
    planner = InvestigationPlanner()

    # --- Connect to remote MCP server ---
    print("[*] Connecting to remote SIFT MCP server via SSH stdio...")
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            print("[+] MCP session initialized.")

            # Discover available tools
            tools_response = await session.list_tools()
            mcp_tools = tools_response.tools
            print(f"[+] Discovered {len(mcp_tools)} MCP tool(s): "
                  f"{', '.join(t.name for t in mcp_tools)}")

            # Convert MCP tool schemas to Gemini FunctionDeclaration format
            gemini_tools = _mcp_tools_to_gemini(mcp_tools)

            # Build initial conversation contents
            contents: list[types.Content] = [
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text=task)],
                )
            ]

            # Environment normalization: ground the model on the canonical evidence root
            contents.append(
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text=(
                        "ENVIRONMENT CONTEXT: The evidence is mounted at "
                        "/cases/case_001/evidence/. ALL tool calls must use "
                        "case_id='case_001' and all file_path arguments must "
                        "be relative to this mount (e.g. 'BOOTNXT' not "
                        "'/cases/case_001/BOOTNXT'). This is the ONLY valid "
                        "evidence root. Do not reference any other path prefix."
                    ))],
                )
            )
            contents.append(
                types.Content(
                    role="model",
                    parts=[types.Part.from_text(text=(
                        "Understood. I will use case_id='case_001' for all "
                        "tool calls and reference all evidence relative to "
                        "/cases/case_001/evidence/."
                    ))],
                )
            )

            # Generation config with system instruction and tools
            config = types.GenerateContentConfig(
                system_instruction=INVESTIGATION_SYSTEM_PROMPT,
                tools=gemini_tools,
                max_output_tokens=4096,
            )

            # Tracking accumulators
            all_findings: list[str] = []
            total_input_tokens = 0
            total_output_tokens = 0
            iteration = 0

            # Reserve iterations for verification
            investigation_cap = max(1, max_iterations - max_verification_iterations)

            # ============================================================
            # PHASE 1: Investigation Loop -- Evidence Collection
            # ============================================================
            while iteration < investigation_cap:
                iteration += 1
                logger.log_iteration(iteration)
                time.sleep(20)
                print(f"\n[Iter {iteration}/{max_iterations}] Sending to model...")

                import time as _time
                max_empty_retries = 3
                empty_attempt = 0
                response = None
                is_empty = True

                iter_i_tok = 0
                iter_o_tok = 0
                iter_cache_r = 0

                while empty_attempt <= max_empty_retries:
                    _max_retries = 5
                    _retry = 0
                    while True:
                        try:
                            response = gemini_client.models.generate_content(
                                model=GEMINI_MODEL,
                                contents=contents,
                                config=config,
                            )
                            break
                        except Exception as _e:
                            err_str = str(_e)
                            if any(code in err_str for code in ["429", "503", "500", "UNAVAILABLE"]) and _retry < _max_retries:
                                _retry += 1
                                import re as _re
                                _match = _re.search(r"retry in (\d+)", err_str)
                                _wait = int(_match.group(1)) + 10 if _match else (15 * _retry)
                                print(f"  [API Transient Error] hit -- waiting {_wait}s before retry {_retry}/{_max_retries} (Error: {err_str[:80]})...")
                                _time.sleep(_wait)
                            else:
                                raise

                    # Token accounting for this attempt
                    if response and response.usage_metadata:
                        iter_i_tok += response.usage_metadata.prompt_token_count or 0
                        iter_o_tok += response.usage_metadata.candidates_token_count or 0
                        iter_cache_r = getattr(response.usage_metadata, "cached_content_token_count", 0) or 0

                    # Check if response has text, tool calls, or usable parts
                    is_empty = True
                    if response and response.candidates:
                        cand = response.candidates[0]
                        if cand.content and cand.content.parts:
                            for part in cand.content.parts:
                                if part.text and part.text.strip():
                                    is_empty = False
                                    break
                                if part.function_call:
                                    is_empty = False
                                    break

                    if not is_empty:
                        break

                    empty_attempt += 1
                    if empty_attempt <= max_empty_retries:
                        print(f"Warning: Gemini returned empty response. Retrying iteration {iteration} (retry {empty_attempt}/{max_empty_retries})...")
                        _time.sleep(5)

                if is_empty:
                    print("session incomplete due to empty model responses")
                    sys.exit("session incomplete due to empty model responses")

                # Token accounting
                total_input_tokens += iter_i_tok
                total_output_tokens += iter_o_tok
                logger.log_token_usage(iteration, iter_i_tok, iter_o_tok, iter_cache_r, 0)
                print(f"    Tokens -> in={iter_i_tok}, out={iter_o_tok}, "
                      f"total_session={total_input_tokens + total_output_tokens}")

                candidate = response.candidates[0]
                finish_reason = candidate.finish_reason

                # Collect text findings and detect function calls
                function_calls = []
                for part in candidate.content.parts:
                    if part.text:
                        all_findings.append(part.text.strip())
                        print(f"\n  [Model]: {part.text[:300]}"
                              + ("..." if len(part.text) > 300 else ""))

                        # --- Parse structured investigation plans ---
                        plans = _parse_investigation_plans(part.text)
                        for p in plans:
                            added_plan = planner.add_plan(
                                p.get("hypothesis", ""),
                                p.get("required_artifacts", []),
                                p.get("tool_selection", ""),
                                p.get("expected_evidence", "")
                            )
                            logger.log_investigation_plan(added_plan)
                            print(f"  [Planner] New investigation plan generated: '{added_plan['hypothesis'][:60]}'")

                        # --- Parse structured evidence claims ---
                        claims = [] if is_tool_validation else _parse_evidence_claims(part.text)
                        for claim_data in claims:
                            original_claim_text = claim_data.get("claim", "")
                            source = claim_data.get("source", "")
                            supporting = claim_data.get("supporting", "")
                            contradiction = claim_data.get("contradictions", "")

                            if not original_claim_text:
                                continue

                            split_claims = _split_broad_claim(original_claim_text)
                            for claim_text in split_claims:
                                if _is_absence_claim(claim_text):
                                    # Do not create a separate finding for absence. Record on related finding only.
                                    related = correlator.find_related(claim_text)
                                    if related:
                                        for eo in related:
                                            gap_msg = f"Absence of evidence ({source}): {claim_text}. Context: {supporting}"
                                            if not hasattr(eo, "evidence_gaps"):
                                                eo.evidence_gaps = []
                                            if gap_msg not in eo.evidence_gaps:
                                                eo.evidence_gaps.append(gap_msg)
                                                print(f"  [Correlator] Recorded evidence gap on {eo.hypothesis_id}: {claim_text}")

                                            # Only add to contradictory_observations if the absence directly disproves the positive claim
                                            if _is_direct_disproof(eo.claim, claim_text):
                                                if gap_msg not in eo.contradictory_observations:
                                                    eo.contradictory_observations.append(gap_msg)
                                                    print(f"  [Correlator] Recorded contradiction (direct disproof) on {eo.hypothesis_id}: {claim_text}")

                                            eo.updated_at = datetime.now(timezone.utc).isoformat()
                                            old_conf = eo.confidence_score
                                            eo.confidence_score = correlator._calculate_confidence(eo)
                                            eo.attack_mappings = MitreAttackMapper.map_finding(eo.claim, eo.evidence_sources, eo.supporting_observations)
                                            logger.log_confidence_update(
                                                eo.finding_id, old_conf, eo.confidence_score,
                                                f"Absence claim recorded: {claim_text[:100]}"
                                            )
                                    continue

                                # Check if this corroborates an existing finding
                                related = correlator.find_related(claim_text)

                                if related:
                                    # Corroborate the most relevant existing finding
                                    eo = related[0]
                                    old_conf = eo.confidence_score
                                    new_conf = correlator.add_corroboration(
                                        eo.finding_id, source, supporting,
                                    )
                                    logger.log_confidence_update(
                                        eo.finding_id, old_conf, new_conf,
                                        f"Corroboration from {source or 'model reasoning'}",
                                    )
                                    print(f"  [Correlator] Corroborated {eo.hypothesis_id}: "
                                          f"{old_conf:.0%} -> {new_conf:.0%}")
                                else:
                                    # Create a new evidence object
                                    eo = correlator.create_evidence(
                                        claim=claim_text,
                                        source=source,
                                        supporting=supporting,
                                    )
                                    logger.log_evidence_created(eo)
                                    print(f"  [Correlator] New evidence {eo.hypothesis_id}: "
                                          f"'{claim_text[:50]}' ({eo.confidence_label})")

                                # Handle contradictions
                                if contradiction:
                                    old_conf = eo.confidence_score
                                    new_conf = correlator.add_contradiction(
                                        eo.finding_id, contradiction, logger=logger
                                    )
                                    logger.log_confidence_update(
                                        eo.finding_id, old_conf, new_conf,
                                        f"Contradiction: {contradiction[:100]}",
                                    )
                                    print(f"  [Correlator] Contradiction on {eo.hypothesis_id}: "
                                          f"{old_conf:.0%} -> {new_conf:.0%}")

                        # Run auto-corroboration after processing all claims
                        auto_corroborate_all_findings(correlator, correlator.observed_store)

                    if part.function_call:
                        function_calls.append(part)

                # --- Consistency check every iteration ---
                passed, issues = check_logical_consistency(all_findings, correlator)
                logger.log_consistency_check(iteration, all_findings, issues, passed)
                if not passed:
                    print("\n  [WARNING]  CONSISTENCY ISSUES DETECTED:")
                    for issue in issues:
                        print(f"     * {issue}")

                # --- End-turn: model is done (STOP with no function calls) ---
                if not function_calls:
                    reason_str = str(finish_reason) if finish_reason else "STOP"
                    logger.log_agent_decision(iteration, reason_str, "Model signalled completion.")
                    print(f"\n[+] Model signalled completion ({reason_str}) at iteration {iteration}.")
                    break

                # --- Function calls: execute MCP tools ---
                # Append the model's response (with function_call parts) to history
                contents.append(candidate.content)

                function_response_parts = []
                for fc_part in function_calls:
                    fc = fc_part.function_call
                    tool_name = fc.name
                    tool_args = dict(fc.args) if fc.args else {}
                    tool_use_id = f"{tool_name}_{iteration}_{len(function_response_parts)}"

                    logger.log_tool_call(iteration, tool_name, tool_use_id, tool_args)
                    print(f"\n  [Tool call] {tool_name}({json.dumps(tool_args)[:200]})")

                    t_start = time.monotonic()
                    try:
                        result = await session.call_tool(tool_name, tool_args)
                        elapsed = (time.monotonic() - t_start) * 1000
                        result_content = result.content
                        logger.log_tool_result(
                            iteration, tool_name, tool_use_id, result_content, elapsed
                        )
                        print(f"  [Tool result] ({elapsed:.0f}ms): "
                              f"{str(result_content)[:300]}")

                        # Feed tool results to timeline
                        timeline.add_events_from_tool_output(tool_name, result_content)

                        # Populate observed store and run auto-corroboration
                        correlator.observed_store.add_from_tool_output(tool_name, result_content)
                        auto_corroborate_all_findings(correlator, correlator.observed_store)

                        # Check timeline consistency and apply penalties if it degrades
                        old_consistency = timeline._last_score
                        new_consistency = timeline.analyze_consistency()
                        timeline._last_score = new_consistency
                        if new_consistency < old_consistency:
                            for contra in timeline.contradictions:
                                logger._write("timeline_contradiction", {"message": contra})
                                print(f"  [Timeline] [WARNING] Contradiction detected: {contra}")
                                for eo in correlator.get_all():
                                    words = re.findall(r"[\w.-]+\.\w{3}", eo.claim)
                                    for w in words:
                                        if w.lower() in contra.lower():
                                            old_conf = eo.confidence_score
                                            eo.confidence_score = max(0.0, eo.confidence_score - 0.15)
                                            logger.log_confidence_update(
                                                eo.finding_id, old_conf, eo.confidence_score,
                                                f"Timeline anomaly penalty: {contra[:100]}"
                                            )

                        function_response_parts.append(
                            types.Part.from_function_response(
                                name=tool_name,
                                response={"result": _truncate_tool_result(result_content)},
                            )
                        )
                    except Exception as exc:
                        elapsed = (time.monotonic() - t_start) * 1000
                        error_msg = f"Tool error: {exc}"
                        logger.log_tool_result(
                            iteration, tool_name, tool_use_id, error_msg, elapsed
                        )
                        print(f"  [Tool ERROR] {error_msg}")
                        function_response_parts.append(
                            types.Part.from_function_response(
                                name=tool_name,
                                response={"error": error_msg},
                            )
                        )

                # Append tool results as a user message back to model
                contents.append(
                    types.Content(
                        role="user",
                        parts=function_response_parts,
                    )
                )
                continue

            else:
                # Loop exhausted without break -> investigation cap hit
                print(f"\n[!] Investigation iteration cap reached ({investigation_cap}). "
                      f"Moving to verification stage.")
                logger.log_agent_decision(
                    iteration,
                    "investigation_cap_reached",
                    f"Investigation loop stopped after {investigation_cap} iterations.",
                )

            # ============================================================
            # PHASE 2: Verification Stage -- Self-Correction Loop
            # ============================================================
            unverified = [
                eo for eo in correlator.get_all()
                if eo.status == "hypothesis"
            ]

            if unverified and not is_tool_validation:
                print(f"\n{'-'*60}")
                print(f"  VERIFICATION STAGE -- {len(unverified)} finding(s) to verify")
                print(f"  Max {max_verification_iterations} verification iteration(s) per finding")
                print(f"{'-'*60}")

                for eo in unverified:
                    verification_prompt = (
                        f"\n--- VERIFICATION REQUIRED ---\n"
                        f"Finding {eo.hypothesis_id}: {eo.claim}\n"
                        f"Current confidence: {eo.confidence_score:.0%} ({eo.confidence_label})\n"
                        f"Supporting evidence: {'; '.join(eo.supporting_observations[:5]) or 'None'}\n"
                        f"Contradictions: {'; '.join(eo.contradictory_observations) or 'None'}\n"
                        f"Sources: {', '.join(eo.evidence_sources) or 'None'}\n\n"
                        f"{_generate_corroboration_prompt(eo)}\n\n"
                        f"As a forensic verifier, challenge this finding:\n"
                        f"1. What additional evidence would corroborate this claim?\n"
                        f"2. What evidence would contradict it?\n"
                        f"3. Use available tools to seek corroboration if possible.\n"
                        f"4. Provide your final assessment.\n\n"
                        f"Emit your assessment as:\n"
                        f"```verification_result\n"
                        f'{{"finding_id": "{eo.finding_id}", '
                        f'"status": "verified|refuted|inconclusive", '
                        f'"reasoning": "your reasoning", '
                        f'"additional_evidence": "what you found", '
                        f'"contradictions_found": "any new contradictions"}}\n'
                        f"```"
                    )

                    contents.append(
                        types.Content(
                            role="user",
                            parts=[types.Part.from_text(text=verification_prompt)],
                        )
                    )

                    v_iter = 0
                    verification_resolved = False

                    while v_iter < max_verification_iterations and iteration < max_iterations:
                        v_iter += 1
                        iteration += 1
                        logger.log_iteration(iteration)
                        time.sleep(15)
                        print(f"\n[Verify {eo.hypothesis_id} -- iter {v_iter}/{max_verification_iterations}]"
                              f" Sending to model...")

                        import time as _time
                        _max_retries = 5
                        _retry = 0
                        while True:
                            try:
                                response = gemini_client.models.generate_content(
                                    model=GEMINI_MODEL,
                                    contents=contents,
                                    config=config,
                                )
                                break
                            except Exception as _e:
                                err_str = str(_e)
                                if any(code in err_str for code in ["429", "503", "500", "UNAVAILABLE"]) and _retry < _max_retries:
                                    _retry += 1
                                    import re as _re
                                    _match = _re.search(r"retry in (\d+)", err_str)
                                    _wait = int(_match.group(1)) + 10 if _match else (15 * _retry)
                                    print(f"  [API Transient Error] hit -- waiting {_wait}s before retry {_retry}/{_max_retries} (Error: {err_str[:80]})...")
                                    _time.sleep(_wait)
                                else:
                                    raise

                        # Token accounting
                        usage = response.usage_metadata
                        i_tok = usage.prompt_token_count or 0
                        o_tok = usage.candidates_token_count or 0
                        cache_r = getattr(usage, "cached_content_token_count", 0) or 0
                        total_input_tokens += i_tok
                        total_output_tokens += o_tok
                        logger.log_token_usage(iteration, i_tok, o_tok, cache_r, 0)

                        candidate = response.candidates[0]

                        # Process text and look for verification result
                        function_calls = []
                        if not candidate.content or not candidate.content.parts:
                            logger.log_agent_decision(iteration, "empty_response",
                                "Model returned empty content, skipping iteration.")
                            print(f"  [Warning] Model returned empty response, continuing...")
                            break
                        for part in candidate.content.parts:
                            if part.text:
                                all_findings.append(part.text.strip())
                                print(f"\n  [Verifier]: {part.text[:300]}"
                                      + ("..." if len(part.text) > 300 else ""))

                                # 1. Parse and apply any new evidence claims from verification response first (corroborations)
                                new_claims = _parse_evidence_claims(part.text)
                                for nc in new_claims:
                                    original_nc_claim = nc.get("claim", "")
                                    nc_source = nc.get("source", "")
                                    nc_supporting = nc.get("supporting", "")
                                    if original_nc_claim:
                                        split_nc_claims = _split_broad_claim(original_nc_claim)
                                        for nc_claim in split_nc_claims:
                                            if _is_absence_claim(nc_claim):
                                                gap_msg = f"Absence of evidence ({nc_source}): {nc_claim}. Context: {nc_supporting}"
                                                if not hasattr(eo, "evidence_gaps"):
                                                    eo.evidence_gaps = []
                                                if gap_msg not in eo.evidence_gaps:
                                                    eo.evidence_gaps.append(gap_msg)
                                                    print(f"  [Verification] Recorded evidence gap on {eo.hypothesis_id}: {nc_claim}")

                                                if _is_direct_disproof(eo.claim, nc_claim):
                                                    if gap_msg not in eo.contradictory_observations:
                                                        eo.contradictory_observations.append(gap_msg)
                                                        print(f"  [Verification] Recorded contradiction (direct disproof) on {eo.hypothesis_id}: {nc_claim}")

                                                eo.updated_at = datetime.now(timezone.utc).isoformat()
                                                old_conf = eo.confidence_score
                                                eo.confidence_score = correlator._calculate_confidence(eo)
                                                eo.attack_mappings = MitreAttackMapper.map_finding(eo.claim, eo.evidence_sources, eo.supporting_observations)
                                                logger.log_confidence_update(
                                                    eo.finding_id, old_conf, eo.confidence_score,
                                                    f"Verification absence claim: {nc_claim[:100]}"
                                                )
                                            else:
                                                old_conf = eo.confidence_score
                                                new_conf = correlator.add_corroboration(
                                                    eo.finding_id, nc_source, nc_supporting,
                                                )
                                                if old_conf != new_conf:
                                                    logger.log_confidence_update(
                                                        eo.finding_id, old_conf, new_conf,
                                                        f"Verification corroboration: {nc_source}",
                                                    )

                                # Run auto-corroboration after processing verification claims
                                auto_corroborate_all_findings(correlator, correlator.observed_store)

                                # 2. Check for verification result block
                                v_result = _parse_verification_result(part.text)
                                if v_result:
                                    # Ensure finding_id matches the current finding we are verifying
                                    result_finding_id = v_result.get("finding_id")
                                    if result_finding_id and result_finding_id != eo.finding_id:
                                        print(f"  [Verification] Skipped verification block for unrelated finding {result_finding_id} (current: {eo.finding_id})")
                                        continue

                                    # Protect verified findings from being downgraded by later inconclusive blocks
                                    if eo.status == "verified":
                                        print(f"  [Verification] Finding {eo.hypothesis_id} is already verified. Ignoring status downgrade/change.")
                                        verification_resolved = True
                                        break

                                    old_conf = eo.confidence_score
                                    new_status = v_result.get("status", "inconclusive")

                                    # Validate status value
                                    if new_status not in ("verified", "refuted", "inconclusive"):
                                        new_status = "inconclusive"

                                    # Apply verification outcome bonus/penalty to confidence score FIRST
                                    if new_status == "verified":
                                        correlator.record_verification(
                                            eo.finding_id,
                                            v_result.get("reasoning", "Verification passed"),
                                            success=True,
                                        )
                                    elif new_status == "refuted":
                                        correlator.record_verification(
                                            eo.finding_id,
                                            v_result.get("reasoning", "Verification failed"),
                                            success=False,
                                        )
                                        new_contra = v_result.get("contradictions_found", "")
                                        if new_contra:
                                            correlator.add_contradiction(eo.finding_id, new_contra, logger=logger)
                                    else:
                                        correlator.record_verification(
                                            eo.finding_id,
                                            v_result.get("reasoning", "Inconclusive"),
                                            success=False,
                                        )

                                    # Hard rule: check confidence threshold AFTER applying verification outcome
                                    if new_status == "verified" and eo.confidence_score < 0.25:
                                        print(f"  [Verification] Blocked verification of {eo.hypothesis_id}: confidence too low ({eo.confidence_score:.2f} < 0.25)")
                                        new_status = "inconclusive"

                                    correlator.finalize(eo.finding_id, new_status)
                                    new_conf = eo.confidence_score

                                    logger.log_verification_step(
                                        eo.finding_id,
                                        eo.hypothesis_id,
                                        v_result.get("reasoning", "")[:200],
                                        new_status,
                                        old_conf,
                                        new_conf,
                                    )
                                    logger.log_confidence_update(
                                        eo.finding_id, old_conf, new_conf,
                                        f"Verification: {new_status}",
                                    )
                                    print(f"  [Verification] {eo.hypothesis_id}: "
                                          f"{new_status.upper()} ({old_conf:.0%} -> {new_conf:.0%})")
                                    verification_resolved = True

                            if part.function_call:
                                function_calls.append(part)

                        # If verification is resolved, move to next finding
                        if verification_resolved:
                            break

                        # If model wants to call tools during verification, execute them
                        if function_calls:
                            contents.append(candidate.content)
                            function_response_parts = []
                            for fc_part in function_calls:
                                fc = fc_part.function_call
                                tool_name = fc.name
                                tool_args = dict(fc.args) if fc.args else {}
                                tool_use_id = f"{tool_name}_v{iteration}_{len(function_response_parts)}"

                                logger.log_tool_call(
                                    iteration, tool_name, tool_use_id, tool_args,
                                    hypothesis_id=eo.hypothesis_id,
                                )
                                print(f"\n  [Verify tool call] {tool_name}({json.dumps(tool_args)[:200]})")

                                t_start = time.monotonic()
                                try:
                                    result = await session.call_tool(tool_name, tool_args)
                                    elapsed = (time.monotonic() - t_start) * 1000
                                    result_content = result.content
                                    logger.log_tool_result(
                                        iteration, tool_name, tool_use_id,
                                        result_content, elapsed,
                                        hypothesis_id=eo.hypothesis_id,
                                    )
                                    print(f"  [Verify tool result] ({elapsed:.0f}ms): "
                                          f"{str(result_content)[:300]}")

                                    # Feed tool results to timeline
                                    timeline.add_events_from_tool_output(tool_name, result_content)

                                    # Populate observed store and run auto-corroboration
                                    correlator.observed_store.add_from_tool_output(tool_name, result_content)
                                    auto_corroborate_all_findings(correlator, correlator.observed_store)

                                    # Check timeline consistency and apply penalties if it degrades
                                    old_consistency = timeline._last_score
                                    new_consistency = timeline.analyze_consistency()
                                    timeline._last_score = new_consistency
                                    if new_consistency < old_consistency:
                                        for contra in timeline.contradictions:
                                            logger._write("timeline_contradiction", {"message": contra})
                                            print(f"  [Timeline] [WARNING] Contradiction detected: {contra}")
                                            for eo_to_penalize in correlator.get_all():
                                                words = re.findall(r"[\w.-]+\.\w{3}", eo_to_penalize.claim)
                                                for w in words:
                                                    if w.lower() in contra.lower():
                                                        old_conf = eo_to_penalize.confidence_score
                                                        eo_to_penalize.confidence_score = max(0.0, eo_to_penalize.confidence_score - 0.15)
                                                        logger.log_confidence_update(
                                                            eo_to_penalize.finding_id, old_conf, eo_to_penalize.confidence_score,
                                                            f"Timeline anomaly penalty: {contra[:100]}"
                                                        )

                                    function_response_parts.append(
                                        types.Part.from_function_response(
                                            name=tool_name,
                                            response={"result": _truncate_tool_result(result_content)},
                                        )
                                    )
                                except Exception as exc:
                                    elapsed = (time.monotonic() - t_start) * 1000
                                    error_msg = f"Tool error: {exc}"
                                    logger.log_tool_result(
                                        iteration, tool_name, tool_use_id,
                                        error_msg, elapsed,
                                        hypothesis_id=eo.hypothesis_id,
                                    )
                                    print(f"  [Verify tool ERROR] {error_msg}")
                                    function_response_parts.append(
                                        types.Part.from_function_response(
                                            name=tool_name,
                                            response={"error": error_msg},
                                        )
                                    )

                            contents.append(
                                types.Content(role="user", parts=function_response_parts)
                            )
                            continue
                        else:
                            # Model stopped without tool calls or verification result
                            break

                    # If verification was not resolved, mark as inconclusive (unless already verified)
                    if not verification_resolved:
                        if eo.status == "verified":
                            print(f"  [Verification] Finding {eo.hypothesis_id} is already verified. Skipping inconclusive fallback.")
                        else:
                            old_conf = eo.confidence_score
                            correlator.record_verification(
                                eo.finding_id,
                                "Verification exhausted without conclusive result",
                                success=False,
                            )
                            correlator.finalize(eo.finding_id, "inconclusive")
                            logger.log_verification_step(
                                eo.finding_id, eo.hypothesis_id,
                                "Verification iterations exhausted",
                                "inconclusive", old_conf, eo.confidence_score,
                            )
                            print(f"  [Verification] {eo.hypothesis_id}: INCONCLUSIVE "
                                  f"(exhausted {max_verification_iterations} iterations)")

            # ============================================================
            # PHASE 3: DFIR Validation -- Knowledge-Driven Rules
            # ============================================================
            all_evidence = correlator.get_all()
            if all_evidence:
                print(f"\n[*] Running DFIR validation on {len(all_evidence)} finding(s)...")
                for eo in all_evidence:
                    dfir_warnings = dfir_validator.validate(eo)
                    if dfir_warnings:
                        rules = [w["rule"] for w in dfir_warnings]
                        logger.log_dfir_validation(eo.finding_id, rules, dfir_warnings)
                        for w in dfir_warnings:
                            old_conf = eo.confidence_score
                            new_conf = correlator.apply_dfir_penalty(
                                eo.finding_id, w["message"],
                            )
                            if old_conf != new_conf:
                                logger.log_confidence_update(
                                    eo.finding_id, old_conf, new_conf,
                                    f"DFIR validation: {w['rule']}",
                                )
                        print(f"  [DFIR] {eo.hypothesis_id}: {len(dfir_warnings)} warning(s) -- "
                              f"[{', '.join(rules)}]")

            # ============================================================
            # PHASE 4: Correlation Report Generation
            # ============================================================
            _print_correlation_report(correlator, timeline, logger)

            logger.log_session_end(
                iteration, total_input_tokens, total_output_tokens, "completed"
            )
            print(f"\n{'='*60}")
            print(f"  Session complete.")
            print(f"  Iterations used : {iteration}/{max_iterations}")
            print(f"  Total tokens    : {total_input_tokens + total_output_tokens}")
            print(f"  Audit log       : {AUDIT_LOG_PATH.resolve()}")
            print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# Connection Diagnostic
# ---------------------------------------------------------------------------

async def test_connection(logger: AuditLogger) -> bool:
    """
    Phase 1: Validate Gemini API key with a minimal generate_content call.
    Phase 2: Establish the SSH stdio MCP handshake, discover available tools,
    and print a formatted report. Does NOT start the agent loop or call any tools.

    Returns True on success, False on any connection or protocol error.
    """

    # -- Phase 1: Gemini API Validation --
    print(f"\n{'='*60}")
    print(f"  TriageForce -- Connection Diagnostic")
    print(f"  Session  : {logger.session_id[:8]}")
    print(f"  Provider : Google Gemini")
    print(f"  Model    : {GEMINI_MODEL}")
    print(f"  Remote   : {REMOTE_HOST}")
    print(f"{'='*60}")

    print("\n[*] Phase 1: Validating Gemini API key...")
    t_api_start = time.monotonic()
    try:
        gemini_client = _get_gemini_client()
        test_response = gemini_client.models.generate_content(
            model=GEMINI_MODEL,
            contents="Respond with exactly: TRIAGEFORCE_OK",
            config=types.GenerateContentConfig(max_output_tokens=32),
        )
        api_ms = (time.monotonic() - t_api_start) * 1000
        reply_text = test_response.text.strip() if test_response.text else "(empty)"
        usage = test_response.usage_metadata

        print(f"[+] Gemini API authentication PASSED ({api_ms:.0f}ms)")
        print(f"    Provider       : Google Gemini")
        print(f"    Model          : {GEMINI_MODEL}")
        print(f"    Auth status    : [OK] authenticated")
        print(f"    Test response  : {reply_text[:100]}")
        print(f"    Tokens used    : {usage.total_token_count}")

        logger._write("connection_test", {
            "phase": "gemini_api",
            "status": "authenticated",
            "provider": "google_gemini",
            "model": GEMINI_MODEL,
            "api_ms": round(api_ms, 2),
            "response_preview": reply_text[:100],
            "tokens_used": usage.total_token_count,
        })

    except Exception as api_exc:
        api_ms = (time.monotonic() - t_api_start) * 1000
        print(f"\n[[FAIL]] Gemini API authentication FAILED ({api_ms:.0f}ms)")
        print(f"    Provider       : Google Gemini")
        print(f"    Model          : {GEMINI_MODEL}")
        print(f"    Auth status    : [FAIL] FAILED")
        print(f"    Error          : {api_exc}")
        logger._write("connection_test", {
            "phase": "gemini_api",
            "status": "failed",
            "error": str(api_exc),
        })
        return False

    # -- Phase 2: MCP / SSH Handshake --
    server_params = StdioServerParameters(
        command=SSH_FLAGS[0],
        args=SSH_FLAGS[1:],
        env=dict(os.environ),
    )

    print(f"\n[*] Phase 2: Opening SSH stdio tunnel to remote SIFT MCP server...")
    t_connect_start = time.monotonic()

    try:
        async with stdio_client(server_params) as (read_stream, write_stream):
            connect_ms = (time.monotonic() - t_connect_start) * 1000
            print(f"[+] SSH process started ({connect_ms:.0f}ms)")

            async with ClientSession(read_stream, write_stream) as session:
                print("[*] Sending MCP initialize handshake...")
                t_init_start = time.monotonic()
                init_result = await session.initialize()
                init_ms = (time.monotonic() - t_init_start) * 1000

                server_name = getattr(
                    getattr(init_result, "serverInfo", None), "name", "<unknown>"
                )
                server_version = getattr(
                    getattr(init_result, "serverInfo", None), "version", "<unknown>"
                )
                print(f"[+] MCP handshake complete ({init_ms:.0f}ms)")
                print(f"    Server name    : {server_name}")
                print(f"    Server version : {server_version}")

                # Log the handshake event
                logger._write("connection_test", {
                    "phase": "mcp_handshake",
                    "status": "handshake_ok",
                    "connect_ms": round(connect_ms, 2),
                    "init_ms": round(init_ms, 2),
                    "server_name": server_name,
                    "server_version": server_version,
                    "remote_host": REMOTE_HOST,
                })

                # Discover tools
                print("\n[*] Requesting tool list from remote server...")
                t_tools_start = time.monotonic()
                tools_response = await session.list_tools()
                tools_ms = (time.monotonic() - t_tools_start) * 1000
                mcp_tools = tools_response.tools

                print(f"[+] Tool discovery complete ({tools_ms:.0f}ms) -- "
                      f"{len(mcp_tools)} tool(s) found\n")

                # Pretty-print each tool with its schema
                if not mcp_tools:
                    print("  (no tools registered on remote server)")
                else:
                    for idx, tool in enumerate(mcp_tools, start=1):
                        print(f"  [{idx:02d}] {tool.name}")
                        if tool.description:
                            # Wrap long descriptions at 60 chars
                            desc = tool.description
                            for line in [desc[i:i+60] for i in range(0, len(desc), 60)]:
                                print(f"        {line}")
                        # Print input schema properties if present
                        schema = getattr(tool, "inputSchema", None) or {}
                        props = schema.get("properties", {})
                        required = set(schema.get("required", []))
                        if props:
                            print(f"        Parameters:")
                            for param_name, param_def in props.items():
                                req_marker = "*" if param_name in required else " "
                                p_type = param_def.get("type", "any")
                                p_desc = param_def.get("description", "")
                                print(f"          {req_marker} {param_name} ({p_type})"
                                      + (f" -- {p_desc[:50]}" if p_desc else ""))
                        print()

                # Log tool inventory
                logger._write("connection_test", {
                    "phase": "tool_discovery",
                    "status": "tools_discovered",
                    "tool_count": len(mcp_tools),
                    "tools_ms": round(tools_ms, 2),
                    "tool_names": [t.name for t in mcp_tools],
                })

                print(f"{'='*60}")
                print(f"  [OK] Connection diagnostic PASSED (all phases)")
                print(f"    * Gemini API    : authenticated")
                print(f"    * MCP handshake : OK")
                print(f"    * Tool discovery: {len(mcp_tools)} tool(s)")
                print(f"  Run with --task \"...\" to start the agent loop.")
                print(f"{'='*60}\n")
                return True

    except BaseException as exc:
        elapsed = (time.monotonic() - t_connect_start) * 1000
        print(f"\n[[FAIL]] MCP Connection diagnostic FAILED ({elapsed:.0f}ms)")
        print(f"    (Gemini API was OK -- SSH/MCP layer failed)")
        print(f"    Top-level exception: {type(exc).__qualname__}: {exc}")

        # -- Full recursive exception tree --
        print(f"\n{'-'*60}")
        print("  FULL EXCEPTION TREE (recursively expanded)")
        print(f"{'-'*60}")
        print(_format_exception_tree(exc))
        print(f"{'-'*60}")

        # -- Standard traceback for completeness --
        print(f"\n  Standard Python traceback:")
        traceback.print_exc()

        # -- Log the full failure details --
        logger._write("connection_test", {
            "phase": "mcp_handshake",
            "status": "failed",
            "elapsed_ms": round(elapsed, 2),
            "error": str(exc),
            "exception_type": f"{type(exc).__module__}.{type(exc).__qualname__}",
            "exception_tree": _format_exception_tree(exc),
        })

        # -- Raw subprocess diagnostic: bypass MCP SDK, capture actual I/O --
        print("\n[*] Running raw SSH subprocess diagnostic to capture server output...")
        _run_raw_ssh_diagnostic()

        # -- MCP-specific troubleshooting --
        print("  MCP initialization troubleshooting:")
        print("    1. Does the server write anything to stdout before MCP starts?")
        print("       (logging, print(), import warnings -> must go to stderr only)")
        print("    2. Does the remote .bashrc/.profile print anything?")
        print(f"       -> ssh -o BatchMode=yes {REMOTE_HOST} cat /dev/null")
        print("       (any output from that = stdout pollution breaking JSON-RPC)")
        print("    3. Is the MCP protocol version compatible between client and server?")
        print("       -> Compare 'mcp' package versions on both sides")
        print("    4. Does FastMCP.run() default to stdio transport?")
        print("       -> Check mcp.server.fastmcp source for transport selection")

        # Re-raise KeyboardInterrupt / SystemExit if they were not wrapped
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise

        return False


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    # Ensure stdout/stderr use UTF-8 encoding to prevent UnicodeEncodeError on Windows
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description=(
            "TriageForce -- Autonomous forensic triage agent (SIFT MCP + Gemini)\n\n"
            "Features:\n"
            "  * Evidence correlation with confidence scoring\n"
            "  * Self-correction via bounded verification loop\n"
            "  * DFIR knowledge-driven validation\n\n"
            "Modes:\n"
            "  --test-connection          Handshake only: verify Gemini API + SSH + MCP tools, then exit\n"
            "  --task \"...\"              Run the full autonomous triage agent loop\n"
            "  --task \"...\" --dry-run    Validate config without SSH/MCP connections"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Mutually exclusive mode group
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--task",
        metavar="TASK",
        help='Forensic task to execute, e.g. "Hash verify the E01 image"',
    )
    mode_group.add_argument(
        "--test-connection",
        action="store_true",
        help=(
            "Validate Gemini API key, establish the SSH stdio MCP handshake, "
            "discover remote tools, and print a diagnostic report. "
            "Does not start the agent loop."
        ),
    )

    parser.add_argument(
        "--max-iterations",
        type=int,
        default=DEFAULT_MAX_ITERATIONS,
        metavar="N",
        help=f"Hard cap on agent loop iterations (default: {DEFAULT_MAX_ITERATIONS})",
    )
    parser.add_argument(
        "--max-verification-iterations",
        type=int,
        default=MAX_VERIFICATION_ITERATIONS,
        metavar="N",
        help=f"Max verification iterations per finding (default: {MAX_VERIFICATION_ITERATIONS})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="(With --task) validate config without making any SSH/MCP connections",
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=AUDIT_LOG_PATH,
        help=f"Path to JSONL audit log file (default: {AUDIT_LOG_PATH})",
    )
    args = parser.parse_args()

    # --dry-run only makes sense alongside --task
    if args.dry_run and args.test_connection:
        parser.error("--dry-run cannot be combined with --test-connection")

    # Enforce iteration cap bounds (only relevant for --task)
    if args.task and (args.max_iterations < 1 or args.max_iterations > 100):
        parser.error(
            f"--max-iterations must be between 1 and 100. "
            f"Got: {args.max_iterations}"
        )

    session_id = str(uuid.uuid4())
    logger = AuditLogger(args.log, session_id)

    import asyncio

    # ---- Route: connection diagnostic ----
    if args.test_connection:
        logger._write("session_start", {
            "mode": "test_connection",
            "provider": "google_gemini",
            "model": GEMINI_MODEL,
            "remote_host": REMOTE_HOST,
        })
        success = False
        try:
            success = asyncio.run(test_connection(logger))
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user.")
            logger._write("session_end", {"outcome": "interrupted"})
            sys.exit(1)
        except BaseException as fatal_exc:
            print("\n[FATAL ERROR during connection test]")
            # Recursively expand ExceptionGroup / TaskGroup errors
            print(f"\n{'-'*60}")
            print("  FULL EXCEPTION TREE (from main handler)")
            print(f"{'-'*60}")
            print(_format_exception_tree(fatal_exc))
            print(f"{'-'*60}")
            print("\n  Standard Python traceback:")
            traceback.print_exc()
            logger._write("session_end", {
                "outcome": "fatal_error",
                "exception_type": f"{type(fatal_exc).__module__}.{type(fatal_exc).__qualname__}",
                "exception_tree": _format_exception_tree(fatal_exc),
            })
            if isinstance(fatal_exc, KeyboardInterrupt):
                sys.exit(1)
            sys.exit(2)
        finally:
            logger.close()  # single guaranteed close point for this branch
        sys.exit(0 if success else 1)

    # ---- Route: full agent loop (--task) ----
    logger.log_session_start(args.task, args.max_iterations, GEMINI_MODEL)
    try:
        asyncio.run(
            run_agent(
                task=args.task,
                max_iterations=args.max_iterations,
                logger=logger,
                dry_run=args.dry_run,
                max_verification_iterations=args.max_verification_iterations,
            )
        )
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        logger.log_session_end(0, 0, 0, "interrupted")
        sys.exit(1)
    except Exception:
        print("\n[FATAL ERROR]")
        traceback.print_exc()
        logger.log_session_end(0, 0, 0, "fatal_error")
        sys.exit(2)
    finally:
        logger.close()


if __name__ == "__main__":
    main()
