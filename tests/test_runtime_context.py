from __future__ import annotations

import json

from ca9.capabilities.models import BlastRadius, CapabilityHit
from ca9.models import Report, Verdict, VerdictResult, Vulnerability
from ca9.runtime_context import ServiceContext, apply_runtime_context, load_runtime_context


def _vuln(pkg="requests"):
    return Vulnerability(
        id="CVE-1", package_name=pkg, package_version="2.31.0", severity="high", title="Test"
    )


def _blast_radius(caps=("exec.shell",)):
    hits = tuple(CapabilityHit(name=c, scope="*", source_file="a.py", asset_ref="a") for c in caps)
    return BlastRadius(capabilities=caps, details=hits, risk_level="high", risk_reasons=())


class TestLoadRuntimeContext:
    def test_loads_from_json(self, tmp_path):
        ctx_file = tmp_path / "ctx.json"
        ctx_file.write_text(
            json.dumps(
                {
                    "name": "payment-service",
                    "criticality": "critical",
                    "behind_auth": True,
                    "network_isolated": False,
                    "rate_limited": True,
                }
            )
        )
        ctx = load_runtime_context(ctx_file)
        assert ctx.name == "payment-service"
        assert ctx.criticality == "critical"
        assert ctx.behind_auth is True
        assert ctx.rate_limited is True
        assert ctx.network_isolated is False

    def test_defaults_for_missing_fields(self, tmp_path):
        ctx_file = tmp_path / "ctx.json"
        ctx_file.write_text("{}")
        ctx = load_runtime_context(ctx_file)
        assert ctx.criticality == "default"
        assert ctx.behind_auth is False


class TestApplyRuntimeContext:
    def test_network_isolated_mitigates_egress(self):
        result = VerdictResult(
            vulnerability=_vuln(),
            verdict=Verdict.REACHABLE,
            reason="imported",
            blast_radius=_blast_radius(("network.egress",)),
        )
        report = Report(results=[result], repo_path=".")
        ctx = ServiceContext(network_isolated=True)

        apply_runtime_context(report, ctx)

        assert len(result.runtime_mitigations) >= 1
        assert any("network-isolated" in m for m in result.runtime_mitigations)
        assert "runtime mitigations" in result.reason

    def test_behind_auth_reduces_surface(self):
        result = VerdictResult(
            vulnerability=_vuln(),
            verdict=Verdict.REACHABLE,
            reason="imported",
            blast_radius=_blast_radius(("exec.shell",)),
        )
        report = Report(results=[result], repo_path=".")
        ctx = ServiceContext(behind_auth=True)

        apply_runtime_context(report, ctx)

        assert any("authentication" in m for m in result.runtime_mitigations)

    def test_sandbox_mitigates_shell(self):
        result = VerdictResult(
            vulnerability=_vuln(),
            verdict=Verdict.REACHABLE,
            reason="imported",
            blast_radius=_blast_radius(("exec.shell",)),
        )
        report = Report(results=[result], repo_path=".")
        ctx = ServiceContext(sandbox=True)

        apply_runtime_context(report, ctx)

        assert any("sandbox" in m for m in result.runtime_mitigations)

    def test_read_only_mitigates_write_caps(self):
        result = VerdictResult(
            vulnerability=_vuln(),
            verdict=Verdict.REACHABLE,
            reason="imported",
            blast_radius=_blast_radius(("filesystem.write", "db.write")),
        )
        report = Report(results=[result], repo_path=".")
        ctx = ServiceContext(read_only=True)

        apply_runtime_context(report, ctx)

        assert any("read-only" in m for m in result.runtime_mitigations)

    def test_no_mitigations_for_unreachable(self):
        result = VerdictResult(
            vulnerability=_vuln(),
            verdict=Verdict.UNREACHABLE_STATIC,
            reason="not imported",
        )
        report = Report(results=[result], repo_path=".")
        ctx = ServiceContext(behind_auth=True, network_isolated=True, sandbox=True)

        apply_runtime_context(report, ctx)

        assert len(result.runtime_mitigations) == 0

    def test_low_criticality_with_mitigations_adjusts_priority(self):
        result = VerdictResult(
            vulnerability=_vuln(),
            verdict=Verdict.REACHABLE,
            reason="imported",
            blast_radius=_blast_radius(("network.egress",)),
        )
        report = Report(results=[result], repo_path=".")
        ctx = ServiceContext(criticality="low", behind_auth=True, network_isolated=True)

        apply_runtime_context(report, ctx)

        assert result.runtime_adjusted_priority == "low"

    def test_critical_service_escalates(self):
        result = VerdictResult(
            vulnerability=_vuln(),
            verdict=Verdict.REACHABLE,
            reason="imported",
            blast_radius=_blast_radius(("exec.shell",)),
        )
        report = Report(results=[result], repo_path=".")
        ctx = ServiceContext(criticality="critical", behind_auth=True)

        apply_runtime_context(report, ctx)

        assert result.runtime_adjusted_priority == "critical"
