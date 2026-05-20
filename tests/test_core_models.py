from __future__ import annotations

from ca9.core.models import Evidence, Finding, Package, RiskSignal, SourceEvidence, package_key


def test_package_key_and_purl_are_normalized():
    package = Package(name="Requests", version="2.31.0")

    assert package.key == "pypi:requests@2.31.0"
    assert package.purl == "pkg:pypi/requests@2.31.0"
    assert package_key("PyPI", "typing_extensions", "4.12.0") == ("pypi:typing-extensions@4.12.0")


def test_npm_package_key_preserves_npm_name_characters():
    package = Package(name="@Socket.IO/Component_Emitter", version="1.0.0", ecosystem="npm")

    assert package.normalized_name == "@socket.io/component_emitter"
    assert package.key == "npm:@socket.io/component_emitter@1.0.0"
    assert package.purl == "pkg:npm/%40socket.io/component_emitter@1.0.0"


def test_finding_fingerprint_is_stable():
    source = SourceEvidence(source="test", path="fixture")
    evidence = Evidence(kind="manifest", description="declared package", source=source)
    signal = RiskSignal(
        signal_type="package_health",
        package_key="pypi:requests@2.31.0",
        evidence=(evidence,),
        metadata={"reason": "example"},
    )
    finding = Finding(
        title="Example package risk",
        signal_type="package_health",
        package_key="pypi:requests@2.31.0",
        signals=(signal,),
        evidence=(evidence,),
    )

    assert (
        finding.fingerprint
        == Finding(
            title="Example package risk",
            signal_type="package_health",
            package_key="pypi:requests@2.31.0",
            signals=(signal,),
            evidence=(evidence,),
        ).fingerprint
    )
    assert len(finding.fingerprint) == 64
