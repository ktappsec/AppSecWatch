# UX suggestions backlog

Usability ideas surfaced during the L7-overhaul review. The first batch shipped
with that change (expandable grouped findings + asset cross-linking, scan presets
+ onboarding, suppression clarity, the in-app `/docs` hub + contextual ⓘ links).
The items below were **deferred** — captured here so they aren't lost. Roughly
ordered by value-to-effort.

## Navigation & wayfinding

- **Breadcrumbs** — scan-detail and asset-detail views drop you in with no path
  back to the list or the parent entity. Add a breadcrumb row
  (`Scans / <id>`, `Assets / <fqdn>`). Low effort, static-export-safe.
- **Command palette (⌘K)** — fuzzy-jump to a page, a recent scan, an asset, or a
  capability doc section. High value for power users; pulls in a small combobox
  dependency. Keep it client-only so static export is unaffected.
- **Sidebar reorganisation** — the flat list is growing. Group into
  *Operate* (Dashboard, Scans, New Scan, Schedules), *Inventory* (Assets),
  *Tuning* (Nuclei, AI Tuning, Suppressions), *Admin* (Settings, Docs). Optional
  collapse state in localStorage.
- **Related-entity links everywhere** — the findings→asset link proved the
  pattern; extend it: asset → its last scan, schedule → its last job, nuclei
  template → findings that used it.

## Lists & scale

- **Pagination / server-side search** on Assets, Scans, and the Nuclei catalog.
  These already paginate at the API; the UI loads a single page. For large
  inventories add a pager + a debounced search box bound to the existing query
  params.
- **Saved filters** — persist the Assets status/group filter and the Findings
  severity filter across navigation (URL or localStorage).

## Settings & safety

- **Progressive disclosure on Settings** — the Scan-configuration card is long.
  Collapse advanced groups (Stealth/identity, the raw-JSON long-tail) behind
  expanders, surfacing only LLM + Engine by default.
- **Undo for destructive actions** — delete asset / suppression / schedule are
  immediate. Add an optimistic toast with an Undo action (re-POST on undo) or a
  soft-delete + restore window.

## Polish

- **AI profile-card overflow** — long `expected_controls` / `reasoning` lists
  overflow the card. Clamp with a "show more" toggle.
- **Schedule next-run preview** — when editing cadence/at_time/weekday, show the
  computed next 2–3 fire times (UTC + local) before saving.
- **Throttle preview on New-Scan** — already shows the active tier's knobs; extend
  to a small comparison so a user can see what dropping to `gentle` changes.
