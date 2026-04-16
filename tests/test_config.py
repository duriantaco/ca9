from __future__ import annotations

from ca9.config import find_config, load_config


class TestFindConfig:
    def test_finds_config_in_current_dir(self, tmp_path):
        config_file = tmp_path / ".ca9.toml"
        config_file.write_text('[ca9]\nrepo = "src"\n')
        result = find_config(tmp_path)
        assert result == config_file

    def test_finds_config_in_parent(self, tmp_path):
        config_file = tmp_path / ".ca9.toml"
        config_file.write_text('repo = "src"\n')
        child = tmp_path / "sub" / "deep"
        child.mkdir(parents=True)
        result = find_config(child)
        assert result == config_file

    def test_returns_none_when_missing(self, tmp_path):
        child = tmp_path / "isolated"
        child.mkdir()
        result = find_config(child)
        assert result is None


class TestLoadConfig:
    def test_loads_config(self, tmp_path):
        config_file = tmp_path / ".ca9.toml"
        config_file.write_text('repo = "src"\nformat = "json"\nverbose = true\n')
        result = load_config(config_file)
        assert result["repo"] == "src"
        assert result["format"] == "json"
        assert result["verbose"] is True

    def test_loads_empty_config(self, tmp_path):
        config_file = tmp_path / ".ca9.toml"
        config_file.write_text("")
        result = load_config(config_file)
        assert result == {}

    def test_loads_namespaced_config_section(self, tmp_path):
        config_file = tmp_path / ".ca9.toml"
        config_file.write_text('[ca9]\nrepo = "src"\nformat = "json"\n')
        result = load_config(config_file)
        assert result["repo"] == "src"
        assert result["format"] == "json"
