from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot
from ca9.core.models import Evidence, Finding, RiskSignal, SourceEvidence

MAX_TEXT_BYTES = 2 * 1024 * 1024

_PTH_SUSPICIOUS_RE = re.compile(
    r"\b(import|exec|eval|compile|subprocess|os\.system|socket|urllib|requests|base64)\b",
    re.I,
)
_SETUP_EXEC_RE = re.compile(
    r"\b(subprocess\.(?:run|call|Popen|check_call|check_output)|os\.system|"
    r"os\.popen|exec\(|eval\(|urllib\.request|requests\.|socket\.)",
    re.I,
)
_ENCODED_EXEC_RE = re.compile(
    r"(base64\.b64decode|zlib\.decompress|marshal\.loads|codecs\.decode|"
    r"binascii\.unhexlify)[\s\S]{0,800}\b(exec|eval|compile|importlib)\b",
    re.I,
)
_STARTUP_CUSTOMIZE_RE = re.compile(
    r"\b(exec|eval|compile|subprocess|os\.system|socket|urllib|requests|base64)\b",
    re.I,
)
_CREDENTIAL_RE = re.compile(
    r"(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GH_TOKEN|"
    r"GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET|\\.ssh/id_rsa|"
    r"\\.ssh/id_ed25519|\\.pypirc|\\.npmrc|id_rsa|id_ed25519|"
    r"PRIVATE KEY|api[_-]?key|access[_-]?token)",
    re.I,
)
_NETWORK_RE = re.compile(
    r"\b(requests\.(?:get|post|put|request)|urllib\.request\.urlopen|"
    r"http\.client|socket\.socket|ftplib\.FTP|smtplib\.SMTP)\b",
    re.I,
)
_SILENT_PROCESS_RE = re.compile(
    r"\b(subprocess\.(?:run|call|Popen|check_call|check_output)|os\.system|os\.popen)\b",
    re.I,
)
_DANGEROUS_TOP_LEVEL_CALLS = {
    "eval",
    "exec",
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.request",
    "urllib.request.urlopen",
    "socket.socket",
}


@dataclass(frozen=True)
class PackageCodeRule:
    id: str
    title: str
    severity: str
    action: str
    confidence: str
    description: str


_PTH_RULE = PackageCodeRule(
    id="python-startup-pth-exec",
    title="Python startup file executes suspicious code",
    severity="critical",
    action="block",
    confidence="high",
    description=".pth files run during interpreter startup; suspicious code here is high risk",
)
_SETUP_RULE = PackageCodeRule(
    id="setup-install-exec",
    title="Install script executes process or network code",
    severity="high",
    action="block",
    confidence="medium",
    description="setup/build code can run during installation",
)
_ENCODED_RULE = PackageCodeRule(
    id="encoded-execution",
    title="Encoded payload is decoded and executed",
    severity="high",
    action="block",
    confidence="medium",
    description="encoded payload execution is common in malicious package loaders",
)
_STARTUP_CUSTOMIZE_RULE = PackageCodeRule(
    id="python-startup-customize-exec",
    title="Python startup customization file contains suspicious behavior",
    severity="critical",
    action="block",
    confidence="high",
    description="sitecustomize.py and usercustomize.py execute automatically during interpreter startup",
)
_CREDENTIAL_EXFIL_RULE = PackageCodeRule(
    id="credential-network-exfiltration",
    title="Package code accesses credentials and network APIs",
    severity="high",
    action="block",
    confidence="medium",
    description="credential access near outbound network code is a common exfiltration pattern",
)
_SILENT_PROCESS_RULE = PackageCodeRule(
    id="silent-process-execution",
    title="Package code can launch external processes",
    severity="medium",
    action="investigate",
    confidence="medium",
    description="unexpected process execution in package code can hide payload download or execution",
)
_IMPORT_TIME_RULE = PackageCodeRule(
    id="import-time-risky-behavior",
    title="Package executes risky behavior at import time",
    severity="high",
    action="block",
    confidence="medium",
    description="top-level package code runs as soon as the module is imported",
)


def analyze_package_snapshots(snapshots: tuple[ArtifactSnapshot, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for snapshot in snapshots:
        for file in snapshot.files:
            text = _read_text_file(file)
            if text is None:
                continue
            findings.extend(_analyze_file(snapshot, file, text))
    return _dedupe_findings(findings)


def _analyze_file(
    snapshot: ArtifactSnapshot,
    file: ArtifactFile,
    text: str,
) -> list[Finding]:
    findings: list[Finding] = []
    lower_path = file.relative_path.lower()

    if lower_path.endswith(".pth"):
        match = _PTH_SUSPICIOUS_RE.search(text)
        if match:
            findings.append(_finding(snapshot, file, text, _PTH_RULE, match.start()))

    if lower_path.endswith("setup.py") or lower_path.endswith("/setup.py"):
        match = _SETUP_EXEC_RE.search(text)
        if match:
            findings.append(_finding(snapshot, file, text, _SETUP_RULE, match.start()))

    if lower_path.endswith(".py") or lower_path.endswith(".pth"):
        match = _ENCODED_EXEC_RE.search(text)
        if match:
            findings.append(_finding(snapshot, file, text, _ENCODED_RULE, match.start()))

    if lower_path.endswith("sitecustomize.py") or lower_path.endswith("usercustomize.py"):
        match = _STARTUP_CUSTOMIZE_RE.search(text)
        if match:
            findings.append(_finding(snapshot, file, text, _STARTUP_CUSTOMIZE_RULE, match.start()))

    if lower_path.endswith(".py"):
        exfil_offset = _credential_network_exfil_offset(text)
        if exfil_offset is not None:
            findings.append(_finding(snapshot, file, text, _CREDENTIAL_EXFIL_RULE, exfil_offset))

        import_time_offset = _top_level_risky_call_offset(text)
        if import_time_offset is not None and not lower_path.endswith("setup.py"):
            findings.append(_finding(snapshot, file, text, _IMPORT_TIME_RULE, import_time_offset))
        elif not lower_path.endswith("setup.py"):
            match = _SILENT_PROCESS_RE.search(text)
            if match:
                findings.append(_finding(snapshot, file, text, _SILENT_PROCESS_RULE, match.start()))

    return findings


def _finding(
    snapshot: ArtifactSnapshot,
    file: ArtifactFile,
    text: str,
    rule: PackageCodeRule,
    offset: int,
) -> Finding:
    line_no, snippet = _line_snippet(text, offset)
    source = SourceEvidence(
        source="package artifact",
        path=f"{snapshot.archive_path}!{file.relative_path}",
        reader="ca9 package-code analyzer",
        detail=rule.id,
    )
    evidence = Evidence(
        kind="package_code",
        description=rule.description,
        source=source,
        metadata={
            "rule_id": rule.id,
            "artifact_kind": snapshot.artifact.kind,
            "artifact_url": snapshot.artifact.url,
            "artifact_hash": snapshot.artifact.hash,
            "file_path": file.relative_path,
            "line": line_no,
            "snippet": snippet,
        },
    )
    signal = RiskSignal(
        signal_type=rule.id,
        package_key=snapshot.package.key,
        severity=rule.severity,
        confidence=rule.confidence,
        evidence=(evidence,),
        metadata={
            "package": snapshot.package.name,
            "version": snapshot.package.version,
            "file_path": file.relative_path,
            "line": line_no,
        },
    )
    return Finding(
        title=f"{rule.title} in {snapshot.package.name}",
        signal_type=rule.id,
        package_key=snapshot.package.key,
        severity=rule.severity,
        signals=(signal,),
        evidence=(evidence,),
        metadata={
            "action": rule.action,
            "reason": rule.description,
            "package": snapshot.package.name,
            "version": snapshot.package.version,
            "dependency_kind": snapshot.package.dependency_kind,
            "policy_id": f"ca9.{rule.id}",
            "file_path": file.relative_path,
            "line": line_no,
        },
    )


def _read_text_file(file: ArtifactFile) -> str | None:
    if file.size > MAX_TEXT_BYTES:
        return None
    try:
        raw = file.path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="ignore")


def _line_snippet(text: str, offset: int) -> tuple[int, str]:
    prefix = text[:offset]
    line_no = prefix.count("\n") + 1
    lines = text.splitlines()
    if 1 <= line_no <= len(lines):
        snippet = lines[line_no - 1].strip()
    else:
        snippet = ""
    if len(snippet) > 240:
        snippet = snippet[:237] + "..."
    return line_no, snippet


def _credential_network_exfil_offset(text: str) -> int | None:
    credential = _CREDENTIAL_RE.search(text)
    network = _NETWORK_RE.search(text)
    if credential is None or network is None:
        return None

    credential_line, _snippet = _line_snippet(text, credential.start())
    network_line, _snippet = _line_snippet(text, network.start())
    if abs(credential_line - network_line) > 80:
        return None
    return min(credential.start(), network.start())


def _top_level_risky_call_offset(text: str) -> int | None:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None

    for node in tree.body:
        call = _top_level_call(node)
        if call is None:
            continue
        name = _call_name(call)
        if name in _DANGEROUS_TOP_LEVEL_CALLS:
            return _offset_for_line(text, getattr(call, "lineno", 1))
    return None


def _top_level_call(node: ast.AST) -> ast.Call | None:
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        return node.value
    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
        return node.value
    if isinstance(node, ast.AnnAssign) and isinstance(node.value, ast.Call):
        return node.value
    if isinstance(node, ast.AugAssign) and isinstance(node.value, ast.Call):
        return node.value
    return None


def _call_name(call: ast.Call) -> str:
    parts: list[str] = []
    current: ast.AST = call.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _offset_for_line(text: str, line_no: int) -> int:
    if line_no <= 1:
        return 0
    offset = 0
    for _index, line in enumerate(text.splitlines(keepends=True), start=1):
        if _index == line_no:
            return offset
        offset += len(line)
    return max(0, len(text) - 1)


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: dict[str, Finding] = {}
    for finding in findings:
        deduped[finding.fingerprint] = finding
    return sorted(
        deduped.values(),
        key=lambda finding: (
            finding.severity,
            finding.signal_type,
            finding.package_key,
            str(finding.metadata.get("file_path") or ""),
        ),
    )
