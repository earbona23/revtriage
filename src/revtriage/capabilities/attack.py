"""A curated subset of MITRE ATT&CK® Enterprise, and the capability taxonomy above it.

Two rules govern this file, and a test enforces both:

1. **Every technique referenced by a rule exists here**, and every technique here has a
   real ATT&CK identifier. A security tool that invents a technique ID is worse than one
   that cites none: the analyst pastes it into a ticket, someone downstream looks it up,
   and the whole report loses credibility. This catalogue is hand-curated for exactly
   that reason — nothing is generated, nothing is guessed.
2. **The catalogue is a subset, and says so.** It covers what these rules map to, not
   ATT&CK as a whole. Coverage claims beyond this list are not made anywhere in the tool.

ATT&CK® is a registered trademark of The MITRE Corporation. This project is not
affiliated with or endorsed by MITRE. Technique names and identifiers are used for
interoperability; the canonical source is https://attack.mitre.org/.
"""

from __future__ import annotations

from dataclasses import dataclass

ATTACK_VERSION_NOTE = (
    "Hand-curated subset of ATT&CK Enterprise. Identifiers and names are reproduced for "
    "interoperability; see https://attack.mitre.org/ for the canonical, current data."
)


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str

    @property
    def url(self) -> str:
        parts = self.id.split(".")
        return f"https://attack.mitre.org/techniques/{parts[0]}/" + (f"{parts[1]}/" if len(parts) > 1 else "")


def _t(id_: str, name: str, tactic: str) -> tuple[str, Technique]:
    return id_, Technique(id_, name, tactic)


TECHNIQUES: dict[str, Technique] = dict(
    [
        # -- execution ---------------------------------------------------------------
        _t("T1059", "Command and Scripting Interpreter", "execution"),
        _t("T1059.001", "Command and Scripting Interpreter: PowerShell", "execution"),
        _t("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "execution"),
        _t("T1059.004", "Command and Scripting Interpreter: Unix Shell", "execution"),
        _t("T1059.005", "Command and Scripting Interpreter: Visual Basic", "execution"),
        _t("T1059.007", "Command and Scripting Interpreter: JavaScript", "execution"),
        _t("T1106", "Native API", "execution"),
        _t("T1204.002", "User Execution: Malicious File", "execution"),
        _t("T1559.002", "Inter-Process Communication: Dynamic Data Exchange", "execution"),
        # -- persistence -------------------------------------------------------------
        _t("T1053.003", "Scheduled Task/Job: Cron", "persistence"),
        _t("T1053.005", "Scheduled Task/Job: Scheduled Task", "persistence"),
        _t("T1197", "BITS Jobs", "persistence"),
        _t("T1543.001", "Create or Modify System Process: Launch Agent", "persistence"),
        _t("T1543.002", "Create or Modify System Process: Systemd Service", "persistence"),
        _t("T1543.003", "Create or Modify System Process: Windows Service", "persistence"),
        _t("T1546.003", "Event Triggered Execution: Windows Management Instrumentation Event Subscription", "persistence"),
        _t("T1546.015", "Event Triggered Execution: Component Object Model Hijacking", "persistence"),
        _t("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "persistence"),
        _t("T1547.009", "Boot or Logon Autostart Execution: Shortcut Modification", "persistence"),
        # -- privilege escalation ----------------------------------------------------
        _t("T1134", "Access Token Manipulation", "privilege-escalation"),
        _t("T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid", "privilege-escalation"),
        _t("T1548.002", "Abuse Elevation Control Mechanism: Bypass User Account Control", "privilege-escalation"),
        # -- injection ---------------------------------------------------------------
        _t("T1055", "Process Injection", "defense-evasion"),
        _t("T1055.001", "Process Injection: Dynamic-link Library Injection", "defense-evasion"),
        _t("T1055.012", "Process Injection: Process Hollowing", "defense-evasion"),
        _t("T1620", "Reflective Code Loading", "defense-evasion"),
        # -- defence evasion ---------------------------------------------------------
        _t("T1036", "Masquerading", "defense-evasion"),
        _t("T1036.007", "Masquerading: Double File Extension", "defense-evasion"),
        _t("T1070.004", "Indicator Removal: File Deletion", "defense-evasion"),
        _t("T1112", "Modify Registry", "defense-evasion"),
        _t("T1218.005", "System Binary Proxy Execution: Mshta", "defense-evasion"),
        _t("T1218.010", "System Binary Proxy Execution: Regsvr32", "defense-evasion"),
        _t("T1218.011", "System Binary Proxy Execution: Rundll32", "defense-evasion"),
        _t("T1221", "Template Injection", "defense-evasion"),
        _t("T1553.002", "Subvert Trust Controls: Code Signing", "defense-evasion"),
        _t("T1562.001", "Impair Defenses: Disable or Modify Tools", "defense-evasion"),
        # -- obfuscation -------------------------------------------------------------
        _t("T1027", "Obfuscated Files or Information", "defense-evasion"),
        _t("T1027.002", "Obfuscated Files or Information: Software Packing", "defense-evasion"),
        _t("T1027.010", "Obfuscated Files or Information: Command Obfuscation", "defense-evasion"),
        _t("T1140", "Deobfuscate/Decode Files or Information", "defense-evasion"),
        # -- anti-analysis -----------------------------------------------------------
        _t("T1497", "Virtualization/Sandbox Evasion", "defense-evasion"),
        _t("T1497.001", "Virtualization/Sandbox Evasion: System Checks", "defense-evasion"),
        _t("T1497.003", "Virtualization/Sandbox Evasion: Time Based Evasion", "defense-evasion"),
        _t("T1622", "Debugger Evasion", "defense-evasion"),
        # -- credential access -------------------------------------------------------
        _t("T1003.001", "OS Credential Dumping: LSASS Memory", "credential-access"),
        _t("T1552.001", "Unsecured Credentials: Credentials In Files", "credential-access"),
        _t("T1555.003", "Credentials from Password Stores: Credentials from Web Browsers", "credential-access"),
        # -- discovery ---------------------------------------------------------------
        _t("T1016", "System Network Configuration Discovery", "discovery"),
        _t("T1033", "System Owner/User Discovery", "discovery"),
        _t("T1057", "Process Discovery", "discovery"),
        _t("T1082", "System Information Discovery", "discovery"),
        _t("T1518.001", "Software Discovery: Security Software Discovery", "discovery"),
        _t("T1614", "System Location Discovery", "discovery"),
        # -- collection --------------------------------------------------------------
        _t("T1005", "Data from Local System", "collection"),
        _t("T1056.001", "Input Capture: Keylogging", "collection"),
        _t("T1113", "Screen Capture", "collection"),
        _t("T1115", "Clipboard Data", "collection"),
        _t("T1123", "Audio Capture", "collection"),
        _t("T1560.001", "Archive Collected Data: Archive via Utility", "collection"),
        # -- command and control -----------------------------------------------------
        _t("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control"),
        _t("T1071.004", "Application Layer Protocol: DNS", "command-and-control"),
        _t("T1090", "Proxy", "command-and-control"),
        _t("T1102", "Web Service", "command-and-control"),
        _t("T1105", "Ingress Tool Transfer", "command-and-control"),
        _t("T1132.001", "Data Encoding: Standard Encoding", "command-and-control"),
        _t("T1573", "Encrypted Channel", "command-and-control"),
        # -- exfiltration ------------------------------------------------------------
        _t("T1041", "Exfiltration Over C2 Channel", "exfiltration"),
        _t("T1048", "Exfiltration Over Alternative Protocol", "exfiltration"),
        _t("T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage", "exfiltration"),
        # -- impact ------------------------------------------------------------------
        _t("T1486", "Data Encrypted for Impact", "impact"),
        _t("T1489", "Service Stop", "impact"),
        _t("T1490", "Inhibit System Recovery", "impact"),
    ]
)


@dataclass(frozen=True)
class Capability:
    """A node in the capability graph."""

    id: str
    title: str
    description: str
    #: Highest number of points this capability may contribute to the score, no matter
    #: how many of its rules fire. See docs/scoring.md.
    cap: int


CAPABILITIES: dict[str, Capability] = {
    c.id: c
    for c in (
        Capability("execution", "Execution", "Runs code or spawns an interpreter.", 12),
        Capability("persistence", "Persistence", "Survives a reboot or a logout.", 18),
        Capability("privilege-escalation", "Privilege escalation", "Tries to gain rights it was not given.", 14),
        Capability("injection", "Process injection", "Places code inside another process.", 20),
        Capability("defense-evasion", "Defence evasion", "Hides from, or disables, host defences.", 16),
        Capability("anti-analysis", "Anti-analysis", "Detects sandboxes, debuggers or analysts and changes behaviour.", 14),
        Capability("obfuscation", "Obfuscation", "Hides its own content or commands from inspection.", 12),
        Capability("credential-access", "Credential access", "Reads or steals secrets.", 20),
        Capability("discovery", "Discovery", "Profiles the host it landed on.", 8),
        Capability("collection", "Collection", "Gathers local data, input or screen content.", 14),
        Capability("command-and-control", "Command and control", "Talks to an operator-controlled endpoint.", 18),
        Capability("exfiltration", "Exfiltration", "Moves data off the host.", 18),
        Capability("impact", "Impact", "Destroys, encrypts or denies access to data or services.", 22),
    )
}

#: Capability pairs that mean far more together than apart. See docs/scoring.md.
LETHAL_COMBINATIONS: tuple[tuple[tuple[str, str], int, str], ...] = (
    (("persistence", "command-and-control"), 10, "survives reboot and calls out — an implant, not a one-shot script"),
    (("credential-access", "exfiltration"), 12, "reads secrets and has a way to send them"),
    (("injection", "anti-analysis"), 10, "injects into other processes and actively resists inspection"),
    (("collection", "exfiltration"), 8, "gathers local data and has a way to send it"),
    (("obfuscation", "execution"), 6, "hides the command it is about to run"),
    (("impact", "discovery"), 8, "profiles the host before destroying data on it"),
    (("execution", "command-and-control"), 6, "runs code fetched from somewhere else"),
)


def technique(identifier: str) -> Technique | None:
    return TECHNIQUES.get(identifier)


def describe(identifiers: tuple[str, ...] | list[str]) -> list[dict]:
    """Resolve technique IDs to full records, skipping unknown ones silently is *not*
    done here — an unknown ID is surfaced, because a rule referencing a technique that is
    not in the catalogue is a bug in the rule, not a display problem."""
    out: list[dict] = []
    for identifier in identifiers:
        found = TECHNIQUES.get(identifier)
        if found is None:
            out.append({"id": identifier, "name": "UNKNOWN TECHNIQUE — not in the catalogue", "tactic": "unknown", "url": ""})
        else:
            out.append({"id": found.id, "name": found.name, "tactic": found.tactic, "url": found.url})
    return out
