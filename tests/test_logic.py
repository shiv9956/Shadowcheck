from shadowcheck.logic import draft_simulation_command, parse_pkg_text, version_in_range


def test_parse_pkg_text() -> None:
    payload = "openssl==3.0.2\n# comment\nnginx==1.24.0"
    out = parse_pkg_text(payload)
    assert out["openssl"] == "3.0.2"
    assert out["nginx"] == "1.24.0"


def test_version_in_range_true() -> None:
    assert version_in_range("1.2.3", ">=1.0,<2.0") is True


def test_version_in_range_false() -> None:
    assert version_in_range("2.4.0", ">=1.0,<2.0") is False


def test_draft_simulation_command() -> None:
    cmd = draft_simulation_command("CVE-2024-3094", "127.0.0.1", 8080)
    assert "Draft-only validation" in cmd
    assert "curl -i" in cmd
