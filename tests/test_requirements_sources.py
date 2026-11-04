from __future__ import annotations

import pytest

from ca9.analyzers.supply_chain import SupplyChainPolicy, analyze_supply_chain
from ca9.inventory import build_inventory

PRIVATE = "https://pypi.acme-internal.example/simple"
SHA = "sha256:" + "a" * 64
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def _packages(repo):
    return {package.name: package for package in build_inventory(repo).packages}


def _signals(repo, **policy):
    inventory = build_inventory(repo)
    findings = analyze_supply_chain(inventory, SupplyChainPolicy(**policy))
    return {(finding.signal_type, finding.metadata["package"]): finding for finding in findings}


def _confusion_policy():
    return {"internal_package_patterns": ("acme-*",), "private_indexes": (PRIVATE,)}


def test_bare_git_and_url_lines_become_named_source_packages(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "git+https://github.com/someone/utilx@main#egg=utilx\n"
        "https://files.evil.example/payload-1.0.tar.gz\n"
        "flask\n"
    )

    packages = _packages(tmp_path)

    assert set(packages) == {"utilx", "payload", "flask"}
    assert packages["utilx"].metadata["source_kind"] == "git"
    assert packages["utilx"].metadata["pinned_commit"] is False
    assert packages["payload"].version == "1.0"
    assert packages["payload"].metadata["source_kind"] == "direct_url"
    assert packages["payload"].metadata["has_hash"] is False
    signals = _signals(tmp_path)
    assert signals[("git_dependency", "utilx")].severity == "medium"
    assert signals[("direct_url_dependency", "payload")].severity == "medium"
    assert ("missing_artifact_hash", "utilx") in signals
    assert ("missing_artifact_hash", "payload") in signals


def test_git_without_egg_takes_the_repository_name(tmp_path):
    (tmp_path / "requirements.txt").write_text("git+ssh://git@github.com/acme/tool.git@v1.2\n")

    assert set(_packages(tmp_path)) == {"tool"}


def test_full_commit_git_and_hashed_url_are_not_mutable(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        f"git+https://github.com/someone/utilx@{COMMIT}#egg=utilx\n"
        f"https://files.example/payload-1.0.tar.gz --hash={SHA}\n"
    )

    signals = _signals(tmp_path)

    git = signals[("git_dependency", "utilx")]
    url = signals[("direct_url_dependency", "payload")]
    assert git.severity == "low"
    assert git.evidence[0].metadata["pinned_commit"] is True
    assert url.severity == "low"
    assert url.evidence[0].metadata["has_hash"] is True
    assert ("missing_artifact_hash", "utilx") not in signals
    assert ("missing_artifact_hash", "payload") not in signals
    assert not any(kind == "mutable_source" for kind, _ in signals)


@pytest.mark.parametrize(
    "ref",
    [
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        COMMIT[:12],
        "v" + COMMIT[1:],
    ],
)
def test_fake_or_short_commit_refs_stay_mutable(tmp_path, ref):
    (tmp_path / "requirements.txt").write_text(
        f"git+https://github.com/someone/utilx@{ref}#egg=utilx\n"
    )

    signals = _signals(tmp_path)

    assert signals[("git_dependency", "utilx")].evidence[0].metadata["pinned_commit"] is False
    assert signals[("git_dependency", "utilx")].severity == "medium"
    assert ("missing_artifact_hash", "utilx") in signals


@pytest.mark.parametrize(
    "pin", ["--hash=", "--hash=sha256:", "--hash=sha256:xyz", "--hash=md5:abc"]
)
def test_empty_or_unusable_hash_pins_still_count_as_unhashed(tmp_path, pin):
    (tmp_path / "requirements.txt").write_text(f"https://files.example/payload-1.0.tar.gz {pin}\n")

    signals = _signals(tmp_path)

    assert signals[("direct_url_dependency", "payload")].evidence[0].metadata["has_hash"] is False
    assert ("missing_artifact_hash", "payload") in signals


@pytest.mark.parametrize(
    "option",
    [
        f"--extra-index-url {PRIVATE}",
        f"--extra-index-url={PRIVATE}",
        f"--extra {PRIVATE}",
        f"--find-links {PRIVATE}",
    ],
)
def test_extra_index_is_merged_with_pypi_and_is_dependency_confusion(tmp_path, option):
    (tmp_path / "requirements.txt").write_text(
        f"{option}\nacme-billing==2.0.0\nACME_Billing.Core==1.0\nrequests==2.32.3\n"
    )

    signals = _signals(tmp_path, **_confusion_policy())

    for name in ("acme-billing", "ACME_Billing.Core"):
        finding = signals[("dependency_confusion", name)]
        assert finding.severity == "critical"
        assert finding.metadata["action"] == "block"
        assert finding.evidence[0].metadata["registry_mode"] == "merged"
    assert not [key for key in signals if key[1] == "requests"]
    assert _packages(tmp_path)["requests"].source_registry is None


@pytest.mark.parametrize("option", [f"--index-url {PRIVATE}", f"-i {PRIVATE}", f"-i{PRIVATE}"])
def test_exclusive_private_index_is_not_dependency_confusion(tmp_path, option):
    (tmp_path / "requirements.txt").write_text(f"{option}\nacme-billing==2.0.0\n")

    signals = _signals(tmp_path, **_confusion_policy())

    assert ("dependency_confusion", "acme-billing") not in signals
    assert _packages(tmp_path)["acme-billing"].source_registry == PRIVATE


def test_merged_indexes_that_are_all_private_are_not_dependency_confusion(tmp_path):
    second = "https://pypi2.acme-internal.example/simple"
    (tmp_path / "requirements.txt").write_text(
        f"--index-url {PRIVATE}\n--extra-index-url {second}\nacme-billing==2.0.0\n"
    )

    signals = _signals(
        tmp_path,
        internal_package_patterns=("acme-*",),
        private_indexes=(PRIVATE, second),
    )

    assert ("dependency_confusion", "acme-billing") not in signals


def test_untrusted_extra_index_is_still_reported_for_public_packages(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "--extra-index-url https://mirror.example/simple\nrequests==2.32.3\n"
    )

    signals = _signals(tmp_path)

    finding = signals[("untrusted_registry", "requests")]
    assert finding.evidence[0].metadata["untrusted_registries"] == ["https://mirror.example/simple"]


def test_internal_git_source_is_not_dependency_confusion_but_registry_one_is(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        f"acme-tools @ git+https://github.com/acme/tools@{COMMIT}\nacme-billing==2.0.0\n"
    )

    signals = _signals(tmp_path, **_confusion_policy())

    assert ("dependency_confusion", "acme-tools") not in signals
    assert ("dependency_confusion", "acme-billing") in signals


def test_index_credentials_are_dropped_before_matching_and_reporting(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "--extra-index-url https://__token__:s3cr3t@pypi.acme-internal.example/simple\n"
        "acme-billing==2.0.0\n"
    )

    signals = _signals(tmp_path, **_confusion_policy())

    finding = signals[("dependency_confusion", "acme-billing")]
    assert PRIVATE in finding.evidence[0].metadata["candidate_registries"]
    assert "s3cr3t" not in str(finding.to_dict())
