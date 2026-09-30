"""src/scripts/install_units.py -- systemd unit templates + host profile. Offline; pytest."""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src" / "scripts"))
import install_units as iu  # noqa: E402

PROFILE = {
    "root": "/srv/ids",
    "python": "/srv/ids/venv/bin/python3",
    "user": "ids",
    "env_file": "/etc/ids/ids.env",
    "units": {
        "soc.service": {"Service": {"SupplementaryGroups": "zeek", "SyslogIdentifier": "home-ids"}},
        "soc-scheduler.service": {"Service": {"ReadWritePaths": ["/opt/zeek/logs", "/var/x"]}},
    },
}


@pytest.mark.parametrize("unit", ["soc.service", "soc-scheduler.service"])
def test_shipped_templates_render_completely(unit):
    text = iu.render_template((ROOT / "systemd" / unit).read_text(encoding="utf-8"), PROFILE)
    assert "@" not in "".join(l for l in text.splitlines() if not l.startswith("#"))
    assert "ExecStart=/srv/ids/venv/bin/python3 /srv/ids/src/" in text
    assert "EnvironmentFile=-/etc/ids/ids.env" in text
    assert "User=ids" in text and "Group=ids" in text
    # no secrets in templates, ever
    assert not [l for l in text.splitlines() if l.startswith("Environment=") and "IDS_SCHEDULER_STANDALONE" not in l]


def test_scheduler_template_is_standalone_and_bounded():
    text = (ROOT / "systemd" / "soc-scheduler.service").read_text(encoding="utf-8")
    assert "Environment=IDS_SCHEDULER_STANDALONE=1" in text
    assert "MemoryMax=" in text and "scheduler.py" in text


def test_unknown_placeholder_refused():
    with pytest.raises(ValueError):
        iu.render_template("ExecStart=@NOPE@\n", PROFILE)


def test_dropin_rendering():
    text = iu.render_dropin({"Service": {"ReadWritePaths": ["/a", "/b"], "NoNewPrivileges": True}})
    assert "[Service]\nReadWritePaths=/a\nReadWritePaths=/b\nNoNewPrivileges=true\n" in text
    assert iu.render_dropin({}) == ""


def test_redact_hides_environment_values_only():
    text = "Environment=TOKEN=abc\nEnvironment=IDS_SCHEDULER_STANDALONE=1\nUser=x\n"
    out = iu.redact(text)
    assert "abc" not in out and "Environment=<redacted>" in out
    assert "IDS_SCHEDULER_STANDALONE=1" in out and "User=x" in out


def test_plan_units_and_dropins(tmp_path):
    items = dict(iu.plan(PROFILE, ROOT / "systemd", tmp_path))
    assert tmp_path / "soc.service" in items
    assert "SupplementaryGroups=zeek" in items[tmp_path / "soc.service.d" / iu.DROPIN_NAME]
    assert items[tmp_path / "soc-scheduler.service.d" / iu.DROPIN_NAME].count("ReadWritePaths=") == 2


def test_stale_dropin_is_removed(tmp_path):
    (tmp_path / "soc.service.d").mkdir()
    (tmp_path / "soc.service.d" / iu.DROPIN_NAME).write_text("old", encoding="utf-8")
    profile = dict(PROFILE, units={"soc.service": {}})
    items = dict(iu.plan(profile, ROOT / "systemd", tmp_path))
    assert items[tmp_path / "soc.service.d" / iu.DROPIN_NAME] == ""


def test_extract_env_moves_missing_keys_only(tmp_path):
    unit = tmp_path / "soc.service"
    unit.write_text("[Service]\nEnvironment=TELEGRAM_TOKEN=t1\nEnvironment=\"API_SECRET_TOKEN=a b\"\n"
                    "Environment=IDS_SCHEDULER_STANDALONE=1\n", encoding="utf-8")
    env = tmp_path / "ids.env"
    env.write_text("TELEGRAM_TOKEN=already\n", encoding="utf-8")
    added = iu.extract_env(unit, env)
    assert added == ["API_SECRET_TOKEN"]
    text = env.read_text(encoding="utf-8")
    assert "TELEGRAM_TOKEN=already" in text and "API_SECRET_TOKEN=a b" in text
    assert "IDS_SCHEDULER_STANDALONE" not in text
    if os.name == "posix":
        assert (env.stat().st_mode & 0o777) == 0o600


def test_dry_run_writes_nothing(tmp_path, capsys):
    import yaml
    profile = tmp_path / "host.yaml"
    profile.write_text(yaml.safe_dump(PROFILE), encoding="utf-8")
    assert iu.main(["--profile", str(profile), "--dest", str(tmp_path / "etc")]) == 0
    assert not (tmp_path / "etc").exists()
    assert "Dry run only" in capsys.readouterr().out
