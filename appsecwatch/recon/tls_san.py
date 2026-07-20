"""tlsx SAN extraction with bounded re-feed loop (DESIGN.md §2.1).

Run tlsx on the live hosts' IPs, extract SANs from served certificates, filter
to configured root domains, dedup via seen-set, hand new names back to dnsx +
triage. Cap iterations at 3. Wildcards (*.foo.com) recorded but not re-fed.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Awaitable

from appsecwatch.config import TlsxConfig
from appsecwatch.logging import RunLogger
from appsecwatch.models import CertInfo, TriagedAsset
from appsecwatch.util.domains import is_wildcard, under_any_root
from appsecwatch.util.subproc import run_tool

MAX_ITERATIONS = 3


def _days_remaining(not_after: str | None) -> int | None:
    if not not_after:
        return None
    try:
        end = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
        return (end - datetime.now(timezone.utc)).days
    except ValueError:
        return None


def _parse_cert(obj: dict[str, Any]) -> CertInfo:
    """Project one tlsx -json record into a CertInfo (inventory only)."""
    issuer = obj.get("issuer_cn")
    orgs = obj.get("issuer_org") or []
    if issuer and orgs:
        issuer = f"{issuer} ({orgs[0]})"
    days = _days_remaining(obj.get("not_after"))
    subject_dn = obj.get("subject_dn")
    issuer_dn = obj.get("issuer_dn")
    return CertInfo(
        ip=obj.get("ip") or obj.get("host") or "",
        subject_cn=obj.get("subject_cn"),
        sans=list(obj.get("subject_an") or []),
        issuer=issuer or obj.get("issuer_dn"),
        serial=obj.get("serial"),
        sha256=(obj.get("fingerprint_hash") or {}).get("sha256"),
        not_before=obj.get("not_before"),
        not_after=obj.get("not_after"),
        days_remaining=days,
        expired=days is not None and days < 0,
        self_signed=bool(subject_dn and issuer_dn and subject_dn == issuer_dn),
        wildcard=bool(obj.get("wildcard_certificate")),
    )


async def _tlsx_grab(
    ips: list[str],
    raw_out: Path,
    cfg: TlsxConfig,
    log: RunLogger,
    timeout: float = 600.0,
) -> tuple[dict[str, list[str]], list[CertInfo]]:
    """Grab certs for the given IPs (one handshake each). Returns
    ({ip: [SAN domains incl. CN]}, [CertInfo]) — the SAN map drives the re-feed
    loop; the CertInfo list is the inventory captured from the same connection.

    NB tlsx 1.1.7 has NO rate-limit flag — `-c` (concurrency) is its pacing knob;
    `-json` already returns the full cert dossier (no -san/-cn/-resp-only needed).
    """
    raw_out.parent.mkdir(parents=True, exist_ok=True)
    if not ips:
        raw_out.write_text("")
        return {}, []

    payload = ("\n".join(sorted(set(ips))) + "\n").encode()
    cmd = [
        "tlsx",
        "-silent",
        "-json",
        "-c", str(cfg.concurrency),
        *cfg.extra_flags,
    ]
    log.debug("running tlsx", cmd=cmd, ip_count=len(ips), concurrency=cfg.concurrency)
    res = await run_tool(cmd, stdin=payload, timeout=timeout, log=log, label="tlsx")
    raw_out.write_bytes(res.stdout)

    by_ip: dict[str, list[str]] = {}
    certs: list[CertInfo] = []
    for line in res.stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        ip = obj.get("ip") or obj.get("host") or ""
        sans = list(obj.get("subject_an") or obj.get("san") or [])
        cn = obj.get("subject_cn") or obj.get("cn")
        if cn:
            sans.append(cn)
        by_ip.setdefault(ip, []).extend(sans)
        certs.append(_parse_cert(obj))
    return by_ip, certs


async def tlsx_refeed_loop(
    initial_assets: list[TriagedAsset],
    roots: list[str],
    cfg: TlsxConfig,
    out_dir: Path,
    log: RunLogger,
    resolve_and_triage: Callable[[list[str], int], Awaitable[list[TriagedAsset]]],
) -> tuple[list[TriagedAsset], list[str], list[CertInfo]]:
    """Run the bounded tlsx -> dnsx -> triage loop.

    Args:
        initial_assets: the live assets after the first triage pass.
        roots: configured root domains; only SANs under these zones are re-fed.
        resolve_and_triage: callback that takes a list of new subdomains and an
            iteration number, runs dnsx + triage on them, and returns the
            resulting TriagedAsset list.

    Returns:
        (final_live_assets, recorded_wildcards, cert_inventory)
    """
    seen_fqdns: set[str] = {a.fqdn for a in initial_assets}
    wildcards: set[str] = set()
    accumulated: dict[str, TriagedAsset] = {a.fqdn: a for a in initial_assets}
    certs_by_ip: dict[str, CertInfo] = {}

    current_assets = initial_assets
    for iteration in range(1, MAX_ITERATIONS + 1):
        ips: list[str] = sorted({ip for a in current_assets for ip in a.a_records})
        if not ips:
            log.info(f"tlsx loop iteration {iteration}: no IPs to query, stopping")
            break

        raw_path = out_dir / f"tlsx-iter{iteration}.jsonl"
        sans_by_ip, certs = await _tlsx_grab(ips, raw_path, cfg, log)
        for c in certs:
            if c.ip:
                certs_by_ip.setdefault(c.ip, c)

        new_names: set[str] = set()
        for ip, sans in sans_by_ip.items():
            for san in sans:
                name = san.strip().lower().rstrip(".")
                if not name:
                    continue
                if is_wildcard(name):
                    wildcards.add(name)
                    continue
                if name in seen_fqdns:
                    continue
                if not under_any_root(name, roots):
                    continue
                new_names.add(name)

        if not new_names:
            log.info(f"tlsx loop iteration {iteration}: no new in-root SANs, stopping")
            break

        log.info(f"tlsx loop iteration {iteration}: discovered {len(new_names)} new SANs in-root")
        seen_fqdns.update(new_names)
        new_triaged = await resolve_and_triage(sorted(new_names), iteration)
        # Only the live ones drive the next iteration (we keep scanning their certs).
        next_live: list[TriagedAsset] = []
        for a in new_triaged:
            accumulated[a.fqdn] = a
            if a.status == "live":
                next_live.append(a)
        current_assets = next_live

    final_live = [a for a in accumulated.values() if a.status == "live"]
    certs = sorted(certs_by_ip.values(), key=lambda c: c.ip)
    annotate_certs_dns(certs, final_live)
    return final_live, sorted(wildcards), certs


def annotate_certs_dns(certs: list[CertInfo], live_assets: list[TriagedAsset]) -> None:
    """Stamp each cert with the DNS relationship between its IP and the scanned hosts.

    The dossier is IP-keyed: tlsx connects to an IP and reads whatever cert is served,
    then that cert names hosts via subject_cn/SANs — which may point their DNS at a
    DIFFERENT IP (shared hosting, a stale/decommissioned endpoint). This fills, per
    cert, from data already in hand (no lookups):

      * `resolving_names` — scanned FQDNs whose DNS actually resolves to this cert's IP.
        Every cert IP came from a live asset's a_records, so this is normally non-empty.
      * `subject_cn_ips` — where the cert's own subject_cn resolves (empty when the CN
        is a wildcard or not among scanned assets → "unknown", never a false "elsewhere").

    A mismatch (`subject_cn` not among `resolving_names`, `subject_cn_ips` pointing
    elsewhere) is the "cert on a stale IP" case — surfaced, not hidden.
    """
    ip_to_fqdns: dict[str, list[str]] = {}
    fqdn_to_ips: dict[str, list[str]] = {}
    for a in live_assets:
        fqdn_to_ips.setdefault(a.fqdn, [])
        for ip in a.a_records:
            ip_to_fqdns.setdefault(ip, []).append(a.fqdn)
            fqdn_to_ips[a.fqdn].append(ip)
    for c in certs:
        c.resolving_names = sorted(ip_to_fqdns.get(c.ip, []))
        cn = (c.subject_cn or "").strip().lower().rstrip(".")
        # Wildcard CNs aren't resolvable names; leave subject_cn_ips empty ("unknown").
        if cn and not is_wildcard(cn) and cn in fqdn_to_ips:
            c.subject_cn_ips = sorted(fqdn_to_ips[cn])
