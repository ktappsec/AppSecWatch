"""Nuclei catalog indexing/search, custom-template CRUD/validate/materialize,
and granular NucleiConfig → command mapping."""
from __future__ import annotations

import appsecwatch.api.nuclei_custom as nc
from appsecwatch.api.db import Database
from appsecwatch.api.nuclei_catalog import NucleiCatalog
from appsecwatch.api.nuclei_custom import CustomTemplateManager, _extract_yaml, validate_template
from appsecwatch.config import NucleiConfig


def _write(p, tid, sev, tags, name="t"):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"id: {tid}\ninfo:\n  name: {name}\n  severity: {sev}\n  tags: {tags}\n")


# --- catalog ---------------------------------------------------------------
def test_catalog_index_and_search(tmp_path):
    root = tmp_path / "templates"
    _write(root / "http" / "cves" / "CVE-2021-1.yaml", "CVE-2021-1", "high", "cve,rce")
    _write(root / "http" / "exposures" / "exp.yaml", "exposure-config", "low", "[exposure]")
    (root / "junk.txt").parent.mkdir(parents=True, exist_ok=True)
    (root / "junk.txt").write_text("not a template")
    cat = NucleiCatalog(Database(tmp_path / "t.db"))
    assert cat.index(root) == 2
    assert {t["id"] for t in cat.search()} == {"CVE-2021-1", "exposure-config"}
    assert [t["id"] for t in cat.search(severity="high")] == ["CVE-2021-1"]
    assert [t["id"] for t in cat.search(category="http/cves")] == ["CVE-2021-1"]
    assert [t["id"] for t in cat.search(tag="rce")] == ["CVE-2021-1"]
    assert {c["category"]: c["count"] for c in cat.categories()} == {
        "http/cves": 1, "http/exposures": 1}


# --- custom templates ------------------------------------------------------
def _force_basic(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError
    monkeypatch.setattr(nc.subprocess, "run", boom)  # → basic structural validate


def test_custom_crud_and_materialize(tmp_path, monkeypatch):
    _force_basic(monkeypatch)
    db = Database(tmp_path / "t.db")
    cat = NucleiCatalog(db)
    m = CustomTemplateManager(db, catalog=cat)
    good = "id: my-check\ninfo:\n  name: My\n  severity: info\n  tags: custom\n"
    row = m.create(name="My", yaml_text=good)
    assert row["valid"] == 1
    # mirrored into the catalog as source=custom
    assert [t["id"] for t in cat.search(source="custom")] == ["my-check"]
    bad = m.create(name="bad", yaml_text="not: a template")
    assert bad["valid"] == 0
    # materialize writes only enabled+valid templates
    d = m.materialize_enabled(tmp_path / "mat")
    assert d and len(list((tmp_path / "mat").glob("*.yaml"))) == 1
    assert m.delete(row["id"]) is True


def test_validate_and_extract(monkeypatch):
    _force_basic(monkeypatch)
    ok, _ = validate_template("id: x\ninfo:\n  name: n\n")
    assert ok is True
    bad, err = validate_template("just: text")
    assert bad is False and err
    assert _extract_yaml("```yaml\nid: x\n```").strip() == "id: x"


# --- granular selection ----------------------------------------------------
def test_nuclei_config_accepts_granular_fields():
    c = NucleiConfig(tags=["cve", "rce"], exclude_tags=["dos"], template_ids=["CVE-x"],
                     templates=["/t/custom"], exclude_templates=["http/dos"])
    assert c.tags == ["cve", "rce"] and c.template_ids == ["CVE-x"]
    assert c.templates == ["/t/custom"] and c.exclude_templates == ["http/dos"]


def test_build_nuclei_cmd_granular(tmp_path):
    from appsecwatch.audit.nuclei_runner import build_nuclei_cmd
    out = tmp_path / "n.jsonl"
    # default: auto-scan on, no explicit selection
    assert "-as" in build_nuclei_cmd(NucleiConfig(), out)
    # explicit tags/ids/templates → flags present + -as suppressed
    cmd = build_nuclei_cmd(
        NucleiConfig(tags=["cve", "exposure"], exclude_tags=["dos"],
                     template_ids=["CVE-2021-x"], templates=["/t/custom"],
                     exclude_templates=["http/dos"]),
        out,
    )
    assert "-as" not in cmd
    assert cmd[cmd.index("-tags") + 1] == "cve,exposure"
    assert cmd[cmd.index("-etags") + 1] == "dos"
    assert cmd[cmd.index("-id") + 1] == "CVE-2021-x"
    assert "/t/custom" in cmd and "http/dos" in cmd
