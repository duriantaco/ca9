from __future__ import annotations

from ca9.core.models import Evidence, Finding, Package, RiskSignal, SourceEvidence, package_key


def test_package_key_and_purl_are_normalized():
    package = Package(name="Requests", version="2.31.0")

    assert package.key == "pypi:requests@2.31.0"
    assert package.purl == "pkg:pypi/requests@2.31.0"
    assert package_key("PyPI", "typing_extensions", "4.12.0") == ("pypi:typing-extensions@4.12.0")


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
