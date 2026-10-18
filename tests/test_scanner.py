"""Tests for ai-lure-package-scanner."""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests

from lure_scanner import cli, scanner

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)


def _packument(name, latest, published, scripts, maintainers):
    return {
        "dist-tags": {"latest": latest},
        "time": {"created": "2020-01-01T00:00:00.000Z", latest: published},
        "versions": {latest: {"scripts": scripts}},
        "maintainers": [{"name": f"m{i}"} for i in range(maintainers)],
    }


PACKUMENTS = {
    "nebula-ai-sdk": _packument(
        "nebula-ai-sdk", "1.0.3", "2026-10-10T09:00:00.000Z",
        {"preinstall": "node preinstall.cjs"}, 1),
    "lodash": _packument(
        "lodash", "4.17.21", "2021-02-20T17:37:53.867Z", {}, 5),
}
DOWNLOADS = {"nebula-ai-sdk": 212, "lodash": 45000000}


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


@pytest.fixture()
def fake_registry(monkeypatch):
    def _get(url, timeout=20):
        if "api.npmjs.org" in url:
            name = url.rsplit("/", 1)[-1]
            return _Resp({"downloads": DOWNLOADS[name], "start": "x", "end": "y",
                          "package": name})
        name = url.rsplit("/", 1)[-1]
        return _Resp(PACKUMENTS[name])
    monkeypatch.setattr(requests, "get", _get)


def test_lure_package_flagged_high_with_all_four_signals(fake_registry):
    deps = scanner.parse_deps(FIXTURES / "sample-package.json")
    results = scanner.scan_deps(deps, offline=None)
    by_name = {r["name"]: r for r in results}
    lure = by_name["nebula-ai-sdk"]
    assert lure["severity"] == "HIGH"
    signal_names = [s["signal"] for s in lure["signals"]]
    assert signal_names == ["ai_lure_name", "published_recently",
                            "low_downloads", "install_scripts"]
    blob = json.dumps(lure["signals"])
    assert "nebula" in blob and "preinstall" in blob and "212" in blob


def test_legit_package_clean(fake_registry):
    deps = scanner.parse_deps(FIXTURES / "sample-package.json")
    results = scanner.scan_deps(deps, offline=None)
    by_name = {r["name"]: r for r in results}
    assert by_name["lodash"]["severity"] == "CLEAN"
    assert by_name["lodash"]["signals"] == []


def test_offline_mode_works(capsys):
    rc = cli.main([str(FIXTURES / "sample-package.json"),
                   "--offline", "--fixture", str(FIXTURES / "registry-fixture.json")])
    assert rc == 1  # HIGH present
    out = capsys.readouterr().out
    assert "nebula-ai-sdk" in out and "HIGH" in out
    assert "lodash" in out and "CLEAN" in out


def test_cli_exit_zero_when_clean(tmp_path, fake_registry):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"dependencies": {"lodash": "^4.17.21"}}))
    rc = cli.main([str(pkg)])
    assert rc == 0


def test_cli_json_output(capsys, fake_registry):
    rc = cli.main([str(FIXTURES / "sample-package.json"), "--json"])
    assert rc == 1
    parsed = json.loads(capsys.readouterr().out)
    assert isinstance(parsed, list) and parsed[1]["severity"] == "HIGH"


def test_cli_missing_file():
    assert cli.main(["/nonexistent/package.json"]) == 2


def test_score_unit_edges():
    meta = {"name": "totally-normal-utils", "latest_version": "2.0.0",
            "latest_published": datetime(2020, 5, 1, tzinfo=timezone.utc),
            "weekly_downloads": 999999, "install_scripts": [], "maintainers": 3}
    assert scanner.score_package(meta, now=NOW)["severity"] == "CLEAN"
    meta["name"] = "gpt-wrapper"
    r = scanner.score_package(meta, now=NOW)
    assert r["severity"] == "LOW" and len(r["signals"]) == 1  # name signal alone != HIGH
