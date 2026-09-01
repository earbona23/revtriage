"""Capability rules: the map from concrete evidence to capability + ATT&CK technique.

A rule fires on one of three kinds of evidence, and may use any combination:

* ``patterns`` — regular expressions searched (case-insensitively) against every text
  layer, including the deobfuscated ones. This is what lets a rule fire on a command that
  only exists *after* base64+XOR — the layer id on the resulting `Match` names where.
* ``symbols``  — lowercase substrings matched against the imported/linked symbol table
  (PE imports, ELF dynamic symbols, Mach-O dylibs). Structural, so attributed to L0.
* ``notes``    — exact structural tags emitted by the extractors (``pe:high-entropy-section``).

Two invariants are enforced by `validate_rules`, which a test calls:

1. every ``capability`` on a rule is a real capability in `attack.CAPABILITIES`;
2. every technique a rule references exists in `attack.TECHNIQUES`.

The weights are triage weights, not probabilities. They express "how much does seeing
this, alone, move my belief that the file is malicious" and are bounded per capability by
the caps in `attack.CAPABILITIES` so that fifty flavours of the same behaviour cannot
run the score away from a file that simply does one thing loudly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..model import Match
from . import attack

#: Pattern rules never scan more than this many bytes of a single layer. A triage tool
#: must stay responsive on a padded multi-megabyte sample; the string table and the
#: shallow decoded layers — where the signal is — sit well inside this bound.
MAX_SCAN = 4_000_000


@dataclass(frozen=True)
class Rule:
    id: str
    capability: str
    name: str
    weight: int
    techniques: tuple[str, ...]
    patterns: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    tier: str = "core"
    _compiled: tuple = field(default=(), repr=False, compare=False)

    def compiled(self) -> tuple[re.Pattern, ...]:
        # Compiled lazily and memoised on first use. Frozen dataclass, so the cache is
        # stashed through object.__setattr__ once.
        if self.patterns and not self._compiled:
            object.__setattr__(
                self, "_compiled", tuple(re.compile(p, re.IGNORECASE) for p in self.patterns)
            )
        return self._compiled


def _evidence(text: str, start: int, end: int, window: int = 48) -> str:
    left = max(0, start - window)
    right = min(len(text), end + window)
    snippet = text[left:right].replace("\n", " ").replace("\r", " ")
    snippet = " ".join(snippet.split())
    return (("…" if left else "") + snippet + ("…" if right < len(text) else ""))[:160]


def run_rules(
    rules: list[Rule],
    texts: list[tuple[str, str]],
    imports: list[str],
    notes: list[str],
) -> list[Match]:
    """Evaluate `rules` against decoded text layers, imported symbols and structural notes."""
    note_set = set(notes)
    import_blob = "\n".join(imports).lower()
    matches: list[Match] = []

    for rule in rules:
        seen_layers: set[str] = set()

        for regex in rule.compiled():
            for layer_id, text in texts:
                if layer_id in seen_layers:
                    continue
                hit = regex.search(text if len(text) <= MAX_SCAN else text[:MAX_SCAN])
                if hit:
                    seen_layers.add(layer_id)
                    matches.append(
                        _make(rule, _evidence(text, hit.start(), hit.end()), layer_id)
                    )

        if rule.symbols and "L0" not in seen_layers:
            for symbol in rule.symbols:
                if symbol.lower() in import_blob:
                    seen_layers.add("L0")
                    matches.append(_make(rule, f"imported symbol matching '{symbol}'", "L0"))
                    break

        if rule.notes and "L0" not in seen_layers:
            for note in rule.notes:
                if note in note_set:
                    seen_layers.add("L0")
                    matches.append(_make(rule, f"structural: {note}", "L0"))
                    break

    return matches


def _make(rule: Rule, evidence: str, layer: str) -> Match:
    return Match(
        rule_id=rule.id,
        capability=rule.capability,
        name=rule.name,
        weight=rule.weight,
        techniques=rule.techniques,
        evidence=evidence,
        layer=layer,
    )


def validate_rules(rules: list[Rule]) -> list[str]:
    """Return a list of integrity problems; empty means the rule set is sound."""
    problems: list[str] = []
    for rule in rules:
        if rule.capability not in attack.CAPABILITIES:
            problems.append(f"{rule.id}: unknown capability '{rule.capability}'")
        for technique in rule.techniques:
            if technique not in attack.TECHNIQUES:
                problems.append(f"{rule.id}: references unknown technique '{technique}'")
        if not (rule.patterns or rule.symbols or rule.notes):
            problems.append(f"{rule.id}: has no matchers")
        try:
            rule.compiled()
        except re.error as exc:
            problems.append(f"{rule.id}: bad regex ({exc})")
    return problems


# ======================================================================================
# CORE rules — free tier. These, and only these, produce the score and the verdict.
# ======================================================================================

CORE_RULES: list[Rule] = [
    # -- execution -------------------------------------------------------------------
    Rule("exec.powershell", "execution", "PowerShell interpreter", 6, ("T1059.001",),
         patterns=(r"\bpowershell(\.exe)?\b", r"\bpwsh\b", r"Invoke-Expression\b", r"\bIEX\b")),
    Rule("exec.cmd", "execution", "Windows command shell", 5, ("T1059.003",),
         patterns=(r"\bcmd(\.exe)?\s*/c\b", r"\bcmd\s*/k\b", r"%COMSPEC%")),
    Rule("exec.unix-shell", "execution", "Unix shell execution", 5, ("T1059.004",),
         patterns=(r"/bin/(ba|z|)sh\b", r"\bsystem\s*\(", r"\bpopen\s*\(", r"\bexecve\b")),
    Rule("exec.vbscript", "execution", "Visual Basic scripting", 5, ("T1059.005",),
         patterns=(r"CreateObject\s*\(", r"WScript\.Shell", r"\bGetObject\s*\(")),
    Rule("exec.javascript", "execution", "JavaScript execution primitive", 5, ("T1059.007",),
         patterns=(r"\beval\s*\(", r"new\s+ActiveXObject", r"\bFunction\s*\(\s*['\"]")),
    Rule("exec.native-api", "execution", "Direct native API execution", 6, ("T1106",),
         patterns=(r"\bCreateProcess[AW]?\b", r"\bShellExecute[AW]?\b", r"\bWinExec\b"),
         symbols=("createprocess", "shellexecute", "winexec")),
    Rule("exec.dde", "execution", "Office DDE command execution", 8, ("T1559.002", "T1204.002"),
         patterns=(r"\bDDEAUTO\b",), notes=("office:dde-field",)),
    Rule("exec.macro-autoexec", "execution", "Macro auto-execution on open", 8,
         ("T1059.005", "T1204.002"), notes=("office:macro-auto-execute",)),

    # -- persistence -----------------------------------------------------------------
    Rule("persist.run-key", "persistence", "Registry Run-key persistence", 8, ("T1547.001",),
         patterns=(r"Software\\+Microsoft\\+Windows\\+CurrentVersion\\+Run",
                   r"CurrentVersion\\+RunOnce")),
    Rule("persist.scheduled-task", "persistence", "Scheduled task", 7, ("T1053.005",),
         patterns=(r"\bschtasks(\.exe)?\b", r"Register-ScheduledTask\b", r"\bTaskScheduler\b")),
    Rule("persist.cron", "persistence", "Cron job", 6, ("T1053.003",),
         patterns=(r"\bcrontab\b", r"/etc/cron\.(d|daily|hourly)\b")),
    Rule("persist.systemd", "persistence", "systemd service unit", 6, ("T1543.002",),
         patterns=(r"systemctl\s+enable\b", r"/etc/systemd/system/", r"\[Service\]\s")),
    Rule("persist.launch-agent", "persistence", "macOS Launch Agent", 7, ("T1543.001",),
         patterns=(r"Library/LaunchAgents/", r"Library/LaunchDaemons/", r"launchctl\s+load\b")),
    Rule("persist.win-service", "persistence", "Windows service install", 7, ("T1543.003",),
         patterns=(r"\bsc(\.exe)?\s+create\b", r"New-Service\b"),
         symbols=("createservice", "openscmanager")),
    Rule("persist.wmi-subscription", "persistence", "WMI event subscription", 9, ("T1546.003",),
         patterns=(r"__EventFilter\b", r"CommandLineEventConsumer\b",
                   r"root\\+subscription\b")),
    Rule("persist.com-hijack", "persistence", "COM hijacking", 8, ("T1546.015",),
         patterns=(r"InprocServer32\b", r"CLSID\\+\{[0-9A-Fa-f-]{36}\}\\+InprocServer32")),
    Rule("persist.bits", "persistence", "BITS job", 6, ("T1197",),
         patterns=(r"\bbitsadmin\b", r"Start-BitsTransfer\b")),

    # -- privilege escalation --------------------------------------------------------
    Rule("privesc.uac-bypass", "privilege-escalation", "UAC bypass", 9, ("T1548.002",),
         patterns=(r"\bfodhelper(\.exe)?\b", r"\beventvwr(\.exe)?\b", r"ICMLuaUtil\b",
                   r"ms-settings\\+shell\\+open")),
    Rule("privesc.setuid", "privilege-escalation", "setuid/setgid abuse", 7, ("T1548.001",),
         patterns=(r"chmod\s+[0-7]*[4267][0-7]{3}\b", r"\bchmod\s+u\+s\b", r"\bsetuid\s*\(")),
    Rule("privesc.token", "privilege-escalation", "Access token manipulation", 8, ("T1134",),
         patterns=(r"SeDebugPrivilege\b", r"AdjustTokenPrivileges\b", r"\bImpersonate\w*Token\b"),
         symbols=("adjusttokenprivileges", "duplicatetokenex", "openprocesstoken")),

    # -- process injection -----------------------------------------------------------
    Rule("inject.remote-thread", "injection", "Remote-thread injection", 12, ("T1055",),
         patterns=(r"\bWriteProcessMemory\b", r"\bCreateRemoteThread\b", r"\bVirtualAllocEx\b",
                   r"\bNtCreateThreadEx\b", r"\bQueueUserAPC\b"),
         symbols=("writeprocessmemory", "createremotethread", "virtualallocex", "queueuserapc")),
    Rule("inject.dll", "injection", "DLL injection", 9, ("T1055.001",),
         patterns=(r"\bLoadLibrary[AW]?\b.*\bCreateRemoteThread\b", r"SetWindowsHookEx.*DLL"),
         symbols=("loadlibrarya", "loadlibraryw")),
    Rule("inject.hollowing", "injection", "Process hollowing", 12, ("T1055.012",),
         patterns=(r"\bNtUnmapViewOfSection\b", r"\bZwUnmapViewOfSection\b",
                   r"SetThreadContext\b.*ResumeThread\b"),
         symbols=("ntunmapviewofsection", "setthreadcontext")),
    Rule("inject.reflective", "injection", "Reflective code loading", 10, ("T1620",),
         patterns=(r"\[Reflection\.Assembly\]::Load", r"\bAssembly\.Load\b",
                   r"reflective\s+load", r"VirtualProtect\b.*PAGE_EXECUTE")),

    # -- defence evasion -------------------------------------------------------------
    Rule("evade.rundll32", "defense-evasion", "rundll32 proxy execution", 7, ("T1218.011",),
         patterns=(r"\brundll32(\.exe)?\b",)),
    Rule("evade.regsvr32", "defense-evasion", "regsvr32 proxy execution", 7, ("T1218.010",),
         patterns=(r"\bregsvr32(\.exe)?\b", r"scrobj\.dll\b")),
    Rule("evade.mshta", "defense-evasion", "mshta proxy execution", 8, ("T1218.005",),
         patterns=(r"\bmshta(\.exe)?\b", r"vbscript:", r"javascript:.*execScript")),
    Rule("evade.double-extension", "defense-evasion", "Double file extension", 6, ("T1036.007",),
         notes=("archive:double-extension",)),
    Rule("evade.masquerade", "defense-evasion", "Masquerading as a system binary", 6, ("T1036",),
         patterns=(r"\\+Windows\\+System32\\+(svchost|lsass|services|csrss)\.exe",
                   r"copy\b.+\\+System32\\+")),
    Rule("evade.self-delete", "defense-evasion", "Self-deletion / indicator removal", 5,
         ("T1070.004",),
         patterns=(r"\bdel\b\s+/[fq]\b", r"\bsdelete\b", r"cmd\s*/c\s+del\b",
                   r"Remove-Item\b.*-Force")),
    Rule("evade.modify-registry", "defense-evasion", "Registry modification", 4, ("T1112",),
         patterns=(r"\breg(\.exe)?\s+add\b", r"Set-ItemProperty\b.*HK",
                   r"RegSetValue[Ex]*[AW]?\b"),
         symbols=("regsetvalue", "regcreatekey")),
    Rule("evade.template-injection", "defense-evasion", "Remote template injection", 9,
         ("T1221",), notes=("office:remote-template", "office:external-relationship")),
    Rule("evade.disable-defender", "defense-evasion", "Disabling defences / AMSI", 9,
         ("T1562.001",),
         patterns=(r"Set-MpPreference\b.*Disable", r"DisableRealtimeMonitoring\b",
                   r"AmsiScanBuffer\b", r"amsiInitFailed\b", r"Add-MpPreference\b.*Exclusion")),
    Rule("evade.code-signing", "defense-evasion", "Trust-control subversion", 5, ("T1553.002",),
         patterns=(r"\bmakecert\b", r"\bsigntool\b", r"Set-AuthenticodeSignature\b")),

    # -- obfuscation -----------------------------------------------------------------
    Rule("obf.packing", "obfuscation", "Packed / high-entropy sections", 8, ("T1027.002",),
         notes=("pe:high-entropy-section", "elf:high-entropy-text", "macho:high-entropy-text",
                "macho:encrypted-segment", "pe:section-virtual-size-inflated")),
    Rule("obf.command", "obfuscation", "Command obfuscation", 6, ("T1027.010",),
         patterns=(r"(?:`[A-Za-z]){3,}", r"\^[a-z]\^[a-z]\^[a-z]",
                   r"-join\s*\(?\s*\[char\]", r"\[string\]::Join\b",
                   r"\{[0-9]\}\{[0-9]\}.*-f\s")),
    Rule("obf.encoded-payload", "obfuscation", "Encoded payload / decode primitive", 7,
         ("T1140",),
         patterns=(r"FromBase64String\b", r"-[Ee]ncodedCommand\b", r"\benc\b\s+[A-Za-z0-9+/]{40}",
                   r"\[Convert\]::FromBase64String", r"base64\s+-d\b", r"atob\s*\(")),
    Rule("obf.general", "obfuscation", "Generic content obfuscation", 4, ("T1027",),
         notes=("pe:import-table-unreadable", "archive:encrypted-entry")),

    # -- anti-analysis ---------------------------------------------------------------
    Rule("anti.debugger", "anti-analysis", "Debugger evasion", 7, ("T1622",),
         patterns=(r"\bIsDebuggerPresent\b", r"CheckRemoteDebuggerPresent\b",
                   r"NtQueryInformationProcess\b", r"\bptrace\s*\(\s*PTRACE_TRACEME"),
         symbols=("isdebuggerpresent", "checkremotedebugger", "ntqueryinformationprocess")),
    Rule("anti.vm", "anti-analysis", "Virtual-machine / sandbox detection", 8, ("T1497.001",),
         patterns=(r"\bVMware\b", r"VirtualBox\b", r"\bVBOX\b", r"\bQEMU\b", r"\bcuckoo\b",
                   r"SbieDll\.dll\b", r"vmtoolsd\b", r"\bwine_get_unix_file_name\b")),
    Rule("anti.timing", "anti-analysis", "Time-based sandbox evasion", 5, ("T1497.003",),
         patterns=(r"Start-Sleep\b\s+-?s?\s*\d{3,}", r"\bSleep\s*\(\s*\d{5,}\s*\)",
                   r"ping\b\s+-n\s+\d{2,}\b", r"timeout\b\s+/t\s+\d{2,}")),
    Rule("anti.generic", "anti-analysis", "Sandbox evasion (generic checks)", 5, ("T1497",),
         patterns=(r"GetTickCount\b.*Sleep", r"NumberOfProcessors\b.*\b[12]\b",
                   r"\bSbieApi", r"sample\.exe|malware\.exe|sandbox")),

    # -- credential access -----------------------------------------------------------
    Rule("cred.lsass", "credential-access", "LSASS credential dumping", 12, ("T1003.001",),
         patterns=(r"\blsass(\.exe)?\b", r"MiniDumpWriteMemory|MiniDumpWriteDump\b",
                   r"\bcomsvcs\.dll\b.*MiniDump", r"\bsekurlsa\b", r"\bmimikatz\b"),
         symbols=("minidumpwritedump",)),
    Rule("cred.browser", "credential-access", "Browser credential theft", 9, ("T1555.003",),
         patterns=(r"Login Data\b", r"cookies\.sqlite\b", r"\\+Chrome\\+User Data\\+",
                   r"moz_logins\b", r"encrypted_key\b.*Local State")),
    Rule("cred.files", "credential-access", "Credentials in files", 6, ("T1552.001",),
         patterns=(r"\.aws\\?/?credentials\b", r"\bid_rsa\b", r"\.ssh\\?/?id_", r"\bunattend\.xml\b",
                   r"password\s*=\s*['\"]")),

    # -- discovery -------------------------------------------------------------------
    Rule("disco.net", "discovery", "Network configuration discovery", 3, ("T1016",),
         patterns=(r"\bipconfig\b", r"\bifconfig\b", r"\bgetmac\b", r"\barp\s+-a\b",
                   r"\bnetsh\b\s+wlan")),
    Rule("disco.user", "discovery", "User discovery", 3, ("T1033",),
         patterns=(r"\bwhoami\b", r"\bquser\b", r"%USERNAME%", r"\bGetUserName[AW]?\b")),
    Rule("disco.process", "discovery", "Process discovery", 3, ("T1057",),
         patterns=(r"\btasklist\b", r"\bps\s+-?aux\b", r"CreateToolhelp32Snapshot\b",
                   r"Get-Process\b"),
         symbols=("createtoolhelp32snapshot", "process32next")),
    Rule("disco.system", "discovery", "System information discovery", 3, ("T1082",),
         patterns=(r"\bsysteminfo\b", r"\buname\s+-a\b", r"GetSystemInfo\b",
                   r"Win32_ComputerSystem\b")),
    Rule("disco.security", "discovery", "Security software discovery", 5, ("T1518.001",),
         patterns=(r"Get-MpComputerStatus\b", r"AntiVirusProduct\b", r"SecurityCenter2\b",
                   r"\bwmic\b.*antivirus")),
    Rule("disco.geo", "discovery", "System location discovery", 4, ("T1614",),
         patterns=(r"ip-api\.com", r"ipinfo\.io", r"GetLocaleInfo[AWEx]*\b",
                   r"GetUserDefaultUILanguage\b")),

    # -- collection ------------------------------------------------------------------
    Rule("collect.keylog", "collection", "Keylogging", 10, ("T1056.001",),
         patterns=(r"\bGetAsyncKeyState\b", r"SetWindowsHookEx\b.*WH_KEYBOARD",
                   r"\bGetKeyboardState\b"),
         symbols=("getasynckeystate", "setwindowshookex")),
    Rule("collect.screen", "collection", "Screen capture", 7, ("T1113",),
         patterns=(r"\bBitBlt\b", r"GetDesktopWindow\b.*GetDC", r"CopyFromScreen\b",
                   r"screenshot"),
         symbols=("bitblt", "getdc")),
    Rule("collect.clipboard", "collection", "Clipboard capture", 6, ("T1115",),
         patterns=(r"\bGetClipboardData\b", r"Get-Clipboard\b", r"OpenClipboard\b"),
         symbols=("getclipboarddata",)),
    Rule("collect.audio", "collection", "Audio capture", 6, ("T1123",),
         patterns=(r"\bwaveInOpen\b", r"\bmciSendString\b.*record", r"AudioRecord\b")),
    Rule("collect.local-data", "collection", "Local data collection", 5, ("T1005",),
         patterns=(r"Get-ChildItem\b.*-Recurse.*\.(docx?|xlsx?|pdf|jpg)\b",
                   r"\bfind\b\s+/\S*\s+-name\b", r"\*\.(doc|docx|xls|xlsx|pdf|txt)\b")),
    Rule("collect.archive", "collection", "Archive collected data", 5, ("T1560.001",),
         patterns=(r"Compress-Archive\b", r"\b7z(a)?\b\s+a\b", r"\brar\b\s+a\b",
                   r"\btar\b\s+-?c[zj]?f\b")),

    # -- command and control ---------------------------------------------------------
    Rule("c2.web", "command-and-control", "Web-protocol C2", 6, ("T1071.001",),
         patterns=(r"https?://[^\s'\"<>]{4,}", r"User-Agent:", r"\bWinHttp\w*\b",
                   r"\bXMLHTTP\b", r"Invoke-WebRequest\b", r"Invoke-RestMethod\b"),
         symbols=("winhttpopen", "internetopen", "httpsendrequest")),
    Rule("c2.dns", "command-and-control", "DNS-based C2", 6, ("T1071.004",),
         patterns=(r"\bnslookup\b", r"DnsQuery[AW_]*\b", r"TXT record", r"\bdig\b\s+\+short")),
    Rule("c2.download", "command-and-control", "Ingress tool transfer", 7, ("T1105",),
         patterns=(r"DownloadString\b", r"DownloadFile\b", r"\bcertutil\b.*-urlcache",
                   r"\bcurl\b\s+-\w*O", r"\bwget\b\s+http", r"BitsTransfer\b",
                   r"\bURLDownloadToFile[AW]?\b"),
         symbols=("urldownloadtofile",)),
    Rule("c2.web-service", "command-and-control", "Web-service C2 (legit host abuse)", 7,
         ("T1102",),
         patterns=(r"pastebin\.com/raw", r"raw\.githubusercontent\.com",
                   r"discord(app)?\.com/api/webhooks", r"api\.telegram\.org/bot",
                   r"\bt\.me/")),
    Rule("c2.proxy", "command-and-control", "Proxy / anonymised C2", 6, ("T1090",),
         patterns=(r"\bsocks[45]\b", r"\.onion\b", r"\btor2web\b", r"127\.0\.0\.1:9050")),
    Rule("c2.encoding", "command-and-control", "Encoded C2 channel", 4, ("T1132.001",),
         patterns=(r"\bcertutil\b.*-encode", r"ToBase64String\b.*Upload")),
    Rule("c2.encrypted", "command-and-control", "Encrypted C2 channel", 5, ("T1573",),
         patterns=(r"AES_?(256|128)\b.*(Socket|http)", r"RC4\b.*(Socket|Send)",
                   r"TLS\b.*pin", r"CryptEncrypt\b.*send")),

    # -- exfiltration ----------------------------------------------------------------
    Rule("exfil.c2", "exfiltration", "Exfiltration over C2", 7, ("T1041",),
         patterns=(r"Invoke-RestMethod\b.*-Method\s+Post", r"\bPOST\b\s+https?://.*(data|upload)",
                   r"HttpSendRequest\b.*POST")),
    Rule("exfil.alt-protocol", "exfiltration", "Exfiltration over alternative protocol", 6,
         ("T1048",),
         patterns=(r"\bftp\b\s+-s:", r"ftp://[^\s'\"]+", r"Send-MailMessage\b",
                   r"smtp\.\w+\.\w+.*(587|465|25)\b")),
    Rule("exfil.cloud", "exfiltration", "Exfiltration to cloud storage", 6, ("T1567.002",),
         patterns=(r"api\.dropboxapi\.com", r"content\.dropboxapi\.com",
                   r"\.s3\.amazonaws\.com", r"drive\.google\.com/uc\?", r"storage\.googleapis\.com")),

    # -- impact ----------------------------------------------------------------------
    Rule("impact.encrypt", "impact", "Data encrypted for impact (ransomware)", 12, ("T1486",),
         patterns=(r"\.locked\b", r"\.encrypted\b", r"README.*DECRYPT", r"YOUR FILES.*ENCRYPTED",
                   r"CryptEncrypt\b.*\*\.", r"AesCryptoServiceProvider\b.*Recurse")),
    Rule("impact.inhibit-recovery", "impact", "Inhibit system recovery", 11, ("T1490",),
         patterns=(r"vssadmin\b.*delete\s+shadows", r"\bwbadmin\b\s+delete",
                   r"bcdedit\b.*recoveryenabled\s+no", r"Delete-VMSnapshot\b",
                   r"WMIC\b.*shadowcopy\s+delete")),
    Rule("impact.service-stop", "impact", "Service / defence stop", 7, ("T1489",),
         patterns=(r"\bnet\s+stop\b", r"Stop-Service\b", r"\btaskkill\b\s+/f\b",
                   r"\bsc(\.exe)?\s+stop\b")),
]


# ======================================================================================
# EXTENDED rules — PRO tier. ADDITIVE ONLY. They are reported in a separate section and
# never feed `scoring.compute_score`, so by construction they cannot change a core
# verdict — they can only add higher-fidelity detail on top of it.
# ======================================================================================

EXTENDED_RULES: list[Rule] = [
    Rule("ext.etw-patch", "defense-evasion", "ETW patching (telemetry blinding)", 6,
         ("T1562.001",), tier="extended",
         patterns=(r"EtwEventWrite\b", r"NtTraceEvent\b", r"EtwpCreateEtwThread\b")),
    Rule("ext.named-pipe-c2", "command-and-control", "Named-pipe C2 channel", 6, ("T1090",),
         tier="extended",
         patterns=(r"\\\\\.\\pipe\\+[A-Za-z0-9_]{3,}", r"CreateNamedPipe[AW]?\b")),
    Rule("ext.ransom-note", "impact", "Ransomware note artefact", 8, ("T1486",),
         tier="extended",
         patterns=(r"HOW_?TO_?DECRYPT", r"ransom", r"bitcoin.*wallet.*decrypt",
                   r"tox\s*id\b.*decrypt")),
    Rule("ext.living-off-the-land", "defense-evasion", "LOLBAS proxy execution", 5,
         ("T1218.011",), tier="extended",
         patterns=(r"\bmsiexec\b\s+/[qi].*http", r"\binstallutil\b", r"\bmsbuild\b.*\.xml",
                   r"\bregasm\b", r"\bpresentationhost\b")),
    Rule("ext.clr-hosting", "injection", "In-memory .NET CLR hosting", 7, ("T1620",),
         tier="extended",
         patterns=(r"ICLRRuntimeHost\b", r"CorBindToRuntime\b", r"clr\.dll\b.*Load")),
]
