from __future__ import annotations

import json

from ca9.capabilities.detectors.agent_frameworks import detect_agent_frameworks
from ca9.capabilities.detectors.agent_tools import detect_agent_tools
from ca9.capabilities.detectors.cloud_storage import detect_cloud_storage
from ca9.capabilities.detectors.egress import detect_egress
from ca9.capabilities.detectors.mcp import detect_mcp
from ca9.capabilities.detectors.prompts import detect_prompts
from ca9.capabilities.detectors.providers import detect_providers
from ca9.capabilities.diff import compute_diff
from ca9.capabilities.models import BlastRadius, CapabilityHit
from ca9.capabilities.normalize import deduplicate_capabilities, is_scope_wider, normalize_scope
from ca9.capabilities.risk import assess_blast_radius_risk
from ca9.capabilities.scanner import scan_capabilities, scan_repository


class TestMCPDetector:
    def test_detects_mcp_servers(self, tmp_path):
        mcp_config = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "allowedRoots": ["/data"],
                },
                "shell-exec": {
                    "command": "bash",
                    "tools": [{"name": "run_command"}],
                },
            }
        }
        (tmp_path / "mcp.json").write_text(json.dumps(mcp_config))

        components, capabilities = detect_mcp(tmp_path)

        assert len(components) == 2
        cap_names = {c.name for c in capabilities}
        assert "filesystem.read" in cap_names
        assert "filesystem.write" in cap_names
        assert "exec.shell" in cap_names

    def test_detects_database_tools(self, tmp_path):
        mcp_config = {
            "mcpServers": {
                "postgres-db": {
                    "command": "node",
                    "tools": [{"name": "query_table"}, {"name": "insert_row"}],
                }
            }
        }
        (tmp_path / "mcp.json").write_text(json.dumps(mcp_config))

        _, capabilities = detect_mcp(tmp_path)
        cap_names = {c.name for c in capabilities}
        assert "db.read" in cap_names
        assert "db.write" in cap_names


class TestProviderDetector:
    def test_detects_openai(self, tmp_path):
        code = "import openai\nclient = openai.OpenAI()\n"
        (tmp_path / "app.py").write_text(code)

        components, capabilities = detect_providers(tmp_path)

        assert len(components) >= 1
        assert any(c.name == "network.egress" for c in capabilities)

    def test_detects_anthropic(self, tmp_path):
        code = "from anthropic import Anthropic\nclient = Anthropic()\n"
        (tmp_path / "agent.py").write_text(code)

        components, _ = detect_providers(tmp_path)
        assert any("anthropic" in c.name for c in components)


class TestEgressDetector:
    def test_detects_external_urls(self, tmp_path):
        code = 'import requests\nrequests.get("https://api.example.org/data")\n'
        (tmp_path / "client.py").write_text(code)

        components, capabilities = detect_egress(tmp_path)

        assert len(components) >= 1
        assert any(c.name == "network.egress" for c in capabilities)

    def test_ignores_localhost(self, tmp_path):
        code = 'import requests\nrequests.get("http://localhost:8080/api")\n'
        (tmp_path / "local.py").write_text(code)

        components, _ = detect_egress(tmp_path)
        assert len(components) == 0


class TestAgentFrameworkDetector:
    def test_detects_langchain(self, tmp_path):
        code = "from langchain import LLMChain\n"
        (tmp_path / "chain.py").write_text(code)

        components, _ = detect_agent_frameworks(tmp_path)
        assert len(components) == 1
        assert "langchain" in components[0].name


class TestCloudStorageDetector:
    def test_detects_s3(self, tmp_path):
        code = "import boto3\ns3 = boto3.client('s3')\ns3.upload_file('a', 'b', 'c')\n"
        (tmp_path / "upload.py").write_text(code)

        components, capabilities = detect_cloud_storage(tmp_path)
        cap_names = {c.name for c in capabilities}
        assert "storage.s3.write" in cap_names


class TestAgentToolDetector:
    def test_detects_langchain_tool(self, tmp_path):
        code = "@tool\ndef fetch_url(url: str):\n    return requests.get(url)\n"
        (tmp_path / "tools.py").write_text(code)

        components, capabilities = detect_agent_tools(tmp_path)
        assert len(components) >= 1
        assert any(c.name == "network.egress" for c in capabilities)


class TestPromptDetector:
    def test_detects_prompt_files(self, tmp_path):
        prompts_dir = tmp_path / "prompts"
        prompts_dir.mkdir()
        (prompts_dir / "system.prompt").write_text("You are a helpful assistant.")

        components, _ = detect_prompts(tmp_path)
        assert len(components) >= 1
        assert any("prompt" in c.name for c in components)


class TestNormalize:
    def test_normalize_scope(self):
        assert normalize_scope("./data") == "data"
        assert normalize_scope("./data/models") == "data/models/**"
        assert normalize_scope("/**") == "/**"
        assert normalize_scope("file.txt") == "file.txt"

    def test_is_scope_wider(self):
        assert is_scope_wider("/data/**", "/**")
        assert not is_scope_wider("/**", "/data/**")
        assert not is_scope_wider("/data/**", "/data/**")

    def test_deduplicate(self):
        from ca9.capabilities.models import Capability

        caps = [
            Capability(name="exec.shell", scope="*", asset="a", evidence=["f:1"]),
            Capability(name="exec.shell", scope="*", asset="a", evidence=["f:2"]),
        ]
        result = deduplicate_capabilities(caps)
        assert len(result) == 1
        assert len(result[0].evidence) == 2


class TestScanner:
    def test_scan_repository_returns_aibom(self, tmp_path):
        (tmp_path / "mcp.json").write_text(
            json.dumps({"mcpServers": {"fs": {"command": "node", "allowedRoots": ["/tmp"]}}})
        )
        (tmp_path / "app.py").write_text("from anthropic import Anthropic\n")

        aibom = scan_repository(tmp_path, quiet=True)

        assert aibom.bom_format == "CycloneDX"
        assert len(aibom.components) > 1

    def test_scan_capabilities_returns_hits(self, tmp_path):
        (tmp_path / "mcp.json").write_text(
            json.dumps(
                {"mcpServers": {"shell-runner": {"command": "bash", "tools": [{"name": "exec"}]}}}
            )
        )

        hits = scan_capabilities(tmp_path)
        assert any(h.name == "exec.shell" for h in hits)


class TestBlastRadius:
    def test_blast_radius_risk(self):
        hits = [
            CapabilityHit(name="exec.shell", scope="*", source_file="tools.py", asset_ref="a"),
            CapabilityHit(
                name="network.egress", scope="api.openai.com", source_file="llm.py", asset_ref="b"
            ),
        ]
        risk = assess_blast_radius_risk(hits)
        assert risk.level in ("high", "critical")
        assert any("shell" in r.lower() for r in risk.reasons)

    def test_blast_radius_to_dict(self):
        br = BlastRadius(
            capabilities=("exec.shell", "network.egress"),
            details=(
                CapabilityHit(name="exec.shell", scope="*", source_file="t.py", asset_ref="a"),
            ),
            risk_level="high",
            risk_reasons=("Attacker gains shell execution",),
        )
        d = br.to_dict()
        assert d["risk_level"] == "high"
        assert "exec.shell" in d["capabilities"]


class TestDiff:
    def test_compute_diff_detects_added_capabilities(self):
        base = {"components": [], "services": [], "metadata": {"properties": []}}
        head = {
            "components": [
                {
                    "bom-ref": "mcp_server:fs",
                    "name": "fs",
                    "type": "service",
                    "version": "1",
                    "properties": [{"name": "ca9.ai.asset.kind", "value": "mcp_server"}],
                }
            ],
            "services": [
                {
                    "name": "ca9.ai.capabilities",
                    "properties": [
                        {
                            "name": "ca9.capability.record",
                            "value": json.dumps(
                                {
                                    "cap": "exec.shell",
                                    "scope": "*",
                                    "asset": "mcp_server:fs",
                                    "evidence": [],
                                }
                            ),
                        }
                    ],
                }
            ],
            "metadata": {"properties": []},
        }

        diff = compute_diff(base, head)
        assert len(diff.assets_added) == 1
        assert len(diff.capabilities_added) == 1
        assert diff.capabilities_added[0].capability == "exec.shell"


class TestRiskCombinations:
    def test_shell_plus_egress_is_critical(self):
        hits = [
            CapabilityHit(name="exec.shell", scope="*", source_file="a.py", asset_ref="a"),
            CapabilityHit(
                name="network.egress", scope="api.com", source_file="b.py", asset_ref="b"
            ),
        ]
        risk = assess_blast_radius_risk(hits)
        assert risk.level == "critical"

    def test_db_write_plus_egress_is_critical(self):
        hits = [
            CapabilityHit(name="db.write", scope="*", source_file="a.py", asset_ref="a"),
            CapabilityHit(
                name="network.egress", scope="api.com", source_file="b.py", asset_ref="b"
            ),
        ]
        risk = assess_blast_radius_risk(hits)
        assert risk.level == "critical"

    def test_db_read_plus_egress_is_high(self):
        hits = [
            CapabilityHit(name="db.read", scope="*", source_file="a.py", asset_ref="a"),
            CapabilityHit(
                name="network.egress", scope="api.com", source_file="b.py", asset_ref="b"
            ),
        ]
        risk = assess_blast_radius_risk(hits)
        assert risk.level == "high"


class TestAgentToolRegex:
    def test_tool_with_parens_detected(self, tmp_path):
        code = (
            '@tool(description="Fetches a URL")\n'
            "def fetch_url(url: str):\n"
            "    return requests.get(url)\n"
        )
        (tmp_path / "tools.py").write_text(code)

        components, capabilities = detect_agent_tools(tmp_path)
        assert len(components) >= 1
        tool_names = [c.name for c in components]
        assert any("fetch_url" in n for n in tool_names)

    def test_bare_tool_in_crewai_file_detected_once(self, tmp_path):
        code = "from crewai import Agent\n\n@tool\ndef search(query: str):\n    pass\n"
        (tmp_path / "tools.py").write_text(code)

        components, capabilities = detect_agent_tools(tmp_path)
        tool_components = [c for c in components if "search" in c.name]
        assert len(tool_components) == 1
        assert "crewai" in tool_components[0].name


class TestEgressPrivateIPs:
    def test_filters_private_192_168(self, tmp_path):
        code = 'import requests\nrequests.get("http://192.168.1.1:8080/api")\n'
        (tmp_path / "client.py").write_text(code)

        components, _ = detect_egress(tmp_path)
        domains = [c.name for c in components]
        assert not any("192.168" in d for d in domains)

    def test_filters_private_10_x(self, tmp_path):
        code = 'import requests\nrequests.get("http://10.0.0.1:9090/data")\n'
        (tmp_path / "client.py").write_text(code)

        components, _ = detect_egress(tmp_path)
        domains = [c.name for c in components]
        assert not any("10.0" in d for d in domains)

    def test_filters_private_172_16(self, tmp_path):
        code = 'import requests\nrequests.get("http://172.16.0.1/api")\n'
        (tmp_path / "client.py").write_text(code)

        components, _ = detect_egress(tmp_path)
        domains = [c.name for c in components]
        assert not any("172.16" in d for d in domains)


class TestPolicyPRLabels:
    def test_empty_pr_labels_no_false_match(self, monkeypatch):
        from ca9.capabilities.policy import _check_approval

        monkeypatch.setenv("PR_LABELS", "")
        assert _check_approval({"mode": "pr_label", "label": ""}) is False

    def test_pr_labels_match(self, monkeypatch):
        from ca9.capabilities.policy import _check_approval

        monkeypatch.setenv("PR_LABELS", "approved,security-reviewed")
        assert _check_approval({"mode": "pr_label", "label": "approved"}) is True

    def test_pr_labels_no_match(self, monkeypatch):
        from ca9.capabilities.policy import _check_approval

        monkeypatch.setenv("PR_LABELS", "wip,draft")
        assert _check_approval({"mode": "pr_label", "label": "approved"}) is False
