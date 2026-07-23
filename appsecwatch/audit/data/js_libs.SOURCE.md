# js_libs.json — vulnerable-JS-library signatures

`js_libs.json` is the **bundled seed** of the retire.js signature repository,
vendored verbatim in upstream format.

| | |
|---|---|
| Upstream | https://github.com/RetireJS/retire.js |
| File | `repository/jsrepository.json` |
| Fetched from | https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json |
| Licence | Apache-2.0 (see upstream `LICENSE.md`) |
| Vendored | 2026-07-21 |

**Do not hand-edit.** It is replaced wholesale by
`appsecwatch.audit.signatures.update_js_libs()` (`POST /signatures/js-libs/update`,
`appsecwatch update-signatures`), which writes the refreshed copy to the signature
store rather than back into the package — this file stays the offline fallback so
an air-gapped scan always has signatures.

`audit/js_libs.py::load_db()` normalizes upstream format into the internal shape
(expanding the `§§version§§` placeholder exactly as retire.js does) and compiles
the patterns. Upstream regexes are JS-flavored; the few Python's `re` cannot
compile are skipped per-pattern.
