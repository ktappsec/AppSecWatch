from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from watchtower import __version__
from watchtower.example_config import EXAMPLE_CONFIG_YAML

# NOTE: heavy modules (runner → playwright, etc.) are imported lazily
# inside the subcommand handlers so that `verify-deps` can run and *report*
# missing dependencies rather than crashing on import.


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="watchtower",
        description="Point-in-time external AppSec audit orchestrator.",
    )
    p.add_argument("-V", "--version", action="version", version=f"watchtower {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # ---- scan ----
    scan = sub.add_parser("scan", help="Run a full audit pipeline")
    scan.add_argument("-c", "--config", required=True, help="Path to YAML config")
    scan.add_argument("-o", "--output-dir", default="/data/runs",
                      help="Where to write run directories (default: /data/runs)")
    scan.add_argument("--progress", choices=("plain", "rich", "quiet"), default="plain",
                      help="Progress output mode for stderr")
    scan.add_argument("-v", "--verbose", action="store_true", help="Verbose debug logs")

    compress = scan.add_mutually_exclusive_group()
    compress.add_argument("--compress", dest="compress", action="store_true", default=True,
                          help="Compress per-stage artifact directories into tar.gz at end of run (default)")
    compress.add_argument("--no-compress", dest="compress", action="store_false",
                          help="Keep raw per-stage artifacts uncompressed for direct inspection")

    scan_sel = scan.add_mutually_exclusive_group()
    scan_sel.add_argument("--only", default=None, metavar="TOKENS",
                          help="Comma-separated capability tokens to run exclusively "
                               "(recon,takeovers,tls,nuclei,headers,supply-chain,ai). The recon "
                               "spine always runs; '--only recon' is discovery-only.")
    scan_sel.add_argument("--skip", default=None, metavar="TOKENS",
                          help="Comma-separated capability tokens to exclude.")
    scan.add_argument("--strict", action="store_true",
                      help="Exit non-zero (code 3) if any stage or per-host error was recorded. "
                           "Default: exit 0 (failures are still in errors.json + the report).")

    # ---- init-config ----
    init = sub.add_parser("init-config",
                          help="Print or write a fully-commented example config")
    init.add_argument("-o", "--output", default=None,
                      help="Write to this path instead of stdout. Refuses to overwrite unless --force.")
    init.add_argument("-f", "--force", action="store_true",
                      help="Overwrite the target file if it exists")

    # ---- serve ----
    serve = sub.add_parser(
        "serve",
        help="Run the authenticated Web API (FastAPI) over the scan engine",
    )
    serve.add_argument("-c", "--config", default=None,
                       help="Optional path to server.yaml (seeds first boot). If omitted, "
                            "the server boots UI-managed (config from the runtime store / UI).")
    serve.add_argument("-o", "--output-dir", default=None,
                       help="Where run directories + the config store live (overrides "
                            "server.yaml output_root; default /data/runs).")
    serve.add_argument("--host", default=None, help="Bind host (overrides server.yaml)")
    serve.add_argument("--port", type=int, default=None, help="Bind port (overrides server.yaml)")
    serve.add_argument("--ui-dir", default=None,
                       help="Serve a built UI (Next static export) from this dir at '/' "
                            "with the API under '/api'. Defaults to $WATCHTOWER_UI_DIR.")

    # ---- verify-deps ----
    verify = sub.add_parser(
        "verify-deps",
        help="Check that required tools, Python modules, and (optionally) MMDB / LLM are reachable",
    )
    verify.add_argument(
        "-c", "--config", default=None,
        help="If supplied, also probe the MMDB at the config's mmdb_path and the LLM endpoint",
    )

    return p


def _count_run_errors(run_dir: Path) -> int:
    """Number of consolidated errors recorded for a run (0 if none / unreadable)."""
    ep = run_dir / "errors.json"
    if not ep.is_file():
        return 0
    try:
        return len(json.loads(ep.read_text()))
    except (json.JSONDecodeError, OSError):
        return 0


def _strict_exit(report: Path, args: argparse.Namespace) -> int:
    """Translate recorded errors into an exit code when --strict is set."""
    if not getattr(args, "strict", False):
        return 0
    n = _count_run_errors(report.parent)
    if n:
        print(f"strict: {n} error(s) recorded this run — exiting 3", file=sys.stderr)
        return 3
    return 0


def _parse_selection(args: argparse.Namespace) -> tuple[set[str] | None, set[str] | None]:
    """Turn --only/--skip comma strings into token sets (or None)."""
    def _toks(v: str | None) -> set[str] | None:
        if not v:
            return None
        return {t.strip() for t in v.split(",") if t.strip()}
    return _toks(getattr(args, "only", None)), _toks(getattr(args, "skip", None))


def _cmd_init_config(args: argparse.Namespace) -> int:
    if args.output is None:
        sys.stdout.write(EXAMPLE_CONFIG_YAML)
        return 0

    out = Path(args.output)
    if out.exists() and not args.force:
        print(f"refusing to overwrite existing file: {out} (use --force)", file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(EXAMPLE_CONFIG_YAML)
    print(f"wrote example config to {out}", file=sys.stderr)
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    from watchtower.config import load_config
    from watchtower.runner import run_scan
    from watchtower.stages.pipeline import SelectionError, resolve_selection

    only, skip = _parse_selection(args)
    try:  # validate tokens before any heavy bootstrap
        resolve_selection(only, skip)
    except SelectionError as e:
        print(f"invalid stage selection: {e}", file=sys.stderr)
        return 2

    cfg = load_config(args.config)
    out_root = Path(args.output_dir)
    out_root.mkdir(parents=True, exist_ok=True)

    try:
        report = asyncio.run(
            run_scan(cfg, out_root, args.progress, args.verbose,
                     compress=args.compress, only=only, skip=skip)
        )
    except SelectionError as e:
        print(f"invalid stage selection: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    print(str(report))
    return _strict_exit(report, args)


def _cmd_serve(args: argparse.Namespace) -> int:
    # Lazy import: keeps fastapi/uvicorn off the critical path for other commands
    # and lets verify-deps report a missing web extra rather than crash on import.
    try:
        from watchtower.api.server import serve
    except ImportError as e:
        print(
            f"serve requires the web extras (fastapi, uvicorn): {e}\n"
            "Install with: pip install 'watchtower[web]'  (or pip install fastapi 'uvicorn[standard]')",
            file=sys.stderr,
        )
        return 1
    try:
        serve(args.config, host=args.host, port=args.port, ui_dir=args.ui_dir,
              output_dir=args.output_dir)
    except KeyboardInterrupt:
        print("\nShutting down.", file=sys.stderr)
    return 0


def _cmd_verify_deps(args: argparse.Namespace) -> int:
    from watchtower.preflight import format_report, run_preflight

    cfg = None
    if args.config:
        from watchtower.config import load_config
        cfg = load_config(args.config)
    report = asyncio.run(run_preflight(cfg))
    print(format_report(report))
    return 0 if report.ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "init-config":
        return _cmd_init_config(args)
    if args.command == "verify-deps":
        return _cmd_verify_deps(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
