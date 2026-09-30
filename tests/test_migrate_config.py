"""src/scripts/migrate_config.py -- deployment config.yaml upgrades without overwriting. Offline; pytest."""
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src" / "scripts"))
import migrate_config as mc  # noqa: E402

EXAMPLE = """\
# header
service_ports:
  # API port
  fastapi_port: 8010
  # WebUI port (new)
  webui_port: 8011

threat_intel_and_ai:
  ollama_model: llama3.1

scheduled_jobs:
  scheduler:
    live_prune:
      enabled: true
      cron: "15 3 * * *"
      essential: true
    new_job:
      enabled: false
      cron: "0 5 * * *"

# how the scheduler runs
scheduler_mode: embedded

brand_new_section:
  # a new option
  new_option: 3
"""

CONFIG = """\
# my deployment
service_ports:
  # API port
  fastapi_port: 9999   # changed on purpose

threat_intel_and_ai:
  ollama_model: llama3
  # old cache ttl
  ollama_cache_ttl_seconds: 604800.0

  my_personal_key: keep-me

scheduled_jobs:
  scheduler:
    live_prune:
      enabled: false
      cron: "15 3 * * *"

misc:
  scheduler_mode: embedded   # lives in another section here
"""


def _run(config=CONFIG, example=EXAMPLE, overrides=None):
    return mc.migrate(config, example, overrides)


def test_adds_removes_and_keeps_values():
    new, report, changed = _run()
    assert changed
    got = yaml.safe_load(new)
    # retired key gone, with its comment
    assert "ollama_cache_ttl_seconds" not in got["threat_intel_and_ai"]
    assert "old cache ttl" not in new
    # existing values untouched, personal key kept
    assert got["service_ports"]["fastapi_port"] == 9999
    assert "# changed on purpose" in new
    assert got["threat_intel_and_ai"]["ollama_model"] == "llama3"
    assert got["threat_intel_and_ai"]["my_personal_key"] == "keep-me"
    assert got["scheduled_jobs"]["scheduler"]["live_prune"]["enabled"] is False
    # missing keys added with their comments, in place
    assert got["service_ports"]["webui_port"] == 8011
    assert "# WebUI port (new)" in new
    assert got["scheduled_jobs"]["scheduler"]["live_prune"]["essential"] is True
    assert got["scheduled_jobs"]["scheduler"]["new_job"] == {"enabled": False, "cron": "0 5 * * *"}
    assert got["brand_new_section"] == {"new_option": 3}


def test_key_in_another_section_is_not_added_twice():
    new, _, _ = _run()
    got = yaml.safe_load(new)
    assert "scheduler_mode" not in got          # not re-added at top level
    assert got["misc"]["scheduler_mode"] == "embedded"


def test_second_run_is_a_no_op():
    new, _, _ = _run()
    again, report, changed = _run(config=new)
    assert not changed and again == new


def test_override_changes_value_and_keeps_trailing_comment():
    new, report, changed = _run(overrides={"scheduler_mode": "external"})
    got = yaml.safe_load(new)
    assert got["misc"]["scheduler_mode"] == "external"
    assert "scheduler_mode: external   # lives in another section here" in new
    assert any("host override" in r for r in report)


def test_override_for_unknown_key_refuses():
    with pytest.raises(ValueError):
        _run(overrides={"no_such_key": 1})


def test_override_must_be_scalar():
    with pytest.raises(ValueError):
        _run(overrides={"scheduler_mode": ["a"]})


def test_addition_order_follows_example():
    example = "s:\n  a: 1\n  b: 2\n  c: 3\n  d: 4\n"
    new, _, _ = mc.migrate("s:\n  a: 1\n", example, None)
    assert [l.strip().split(":")[0] for l in new.splitlines() if l.startswith("  ")] == ["a", "b", "c", "d"]


def test_removal_leaves_no_double_blank_line():
    config = "s:\n  a: 1\n\n  # doc\n  ollama_cache_ttl_seconds: 1\n\n  b: 2\n"
    new, _, _ = mc.migrate(config, "s:\n  a: 1\n  b: 2\n", None)
    assert new == "s:\n  a: 1\n\n  b: 2\n"


def test_apply_writes_backup_and_dry_run_does_not(tmp_path):
    cfg = tmp_path / "config.yaml"
    ex = tmp_path / "config.yaml.example"
    cfg.write_text(CONFIG, encoding="utf-8")
    ex.write_text(EXAMPLE, encoding="utf-8")
    assert mc.main(["--config", str(cfg), "--example", str(ex)]) == 0
    assert cfg.read_text(encoding="utf-8") == CONFIG
    assert mc.main(["--config", str(cfg), "--example", str(ex), "--apply"]) == 0
    assert cfg.read_text(encoding="utf-8") != CONFIG
    backups = list(tmp_path.glob("config.yaml.bak-*-migrate"))
    assert len(backups) == 1 and backups[0].read_text(encoding="utf-8") == CONFIG


def test_real_example_files_parse_and_migrate_themselves_cleanly():
    root = Path(__file__).resolve().parent.parent
    for ex in (root / "config.yaml.example", root / "docker" / "config" / "ids" / "config.yaml.example"):
        if not ex.exists():
            continue
        text = ex.read_text(encoding="utf-8")
        new, report, changed = mc.migrate(text, text, None)
        assert not changed, report
