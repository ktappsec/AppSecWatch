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

## EASM & capture follow-ups (deferred from the rendered-profiling / surface work)

The crawler now captures a structure-only manifest (resources, XHR/fetch endpoints,
cookie/storage **key names** — never values) and persists a curated per-asset
**surface** blob. These extend that foundation; all deliberately deferred.

- **Fleet-wide connection graph.** The per-asset surface answers "what does *this*
  host call?". Promote it to a normalized `observations` table (asset → {3rd-party
  domain | endpoint | storage-key} edges) so the dashboard can answer the real EASM
  queries: "which of my assets call `doubleclick.net`?", "my full external-domain
  exposure ranked by host count", "every asset that stashes a token in localStorage".
  This is the actual EASM substrate — its own table, endpoints, and UI view.
- **Over-time change tracking / surface + visual diffing.** "This host started
  calling a new 3rd-party domain (or its screenshot changed) since last scan." The
  one EASM staple that genuinely breaks the locked *point-in-time, no-delta* design,
  so it needs an explicit decision and a history store, not a slip-in.
- **CDP initiator chain.** We capture transitively-loaded scripts (network-level
  hook) but not the *edge* — which script pulled which. A `context.new_cdp_session`
  + `Network.requestWillBeSent` `initiator.stack` would attribute
  "app.js → loaded → evil-cdn.com/x.js" (remediation narrative). Noisy against
  minified bundles; improves attribution, not detection. Defer until the
  supply-chain view actually consumes a dependency graph.
- **Multimodal profiling.** Screenshots are captured for the dashboard today but
  never sent to the LLM. If WatchTower is pointed at a vision-capable model, feed the
  screenshot to the profiler as an extra signal. Gate behind a dedicated flag (only
  meaningful with a multimodal endpoint); the capture seam already exists.
- **localStorage-token as a finding.** The new `storage_keys` capture means a
  token-like key (`access_token` / `id_token` / `jwt` / `refresh_token` in
  localStorage) is now observable — and it's an XSS-exfiltratable secret store.
  Promote it from a profiling signal to a deterministic `Finding` (its own
  `check_id`, low/medium severity, AI-triageable). Decide severity + matching rules
  once there's real captured data to calibrate against.
