"""The canonical example config, bundled as a string constant so `watchtower
init-config` works without relying on package_data discovery quirks."""

EXAMPLE_CONFIG_YAML = """\
# WatchTower configuration example
#
# Required top-level keys: roots, llm. Everything else has sensible defaults.
# Scope is your roots: every host UNDER these that resolves gets the full scan,
# regardless of where it's hosted (no IP/ASN ownership gate).

roots:
  - example.com
  - example-corp.io

# Optional: MaxMind GeoLite2-ASN MMDB for ASN/org enrichment. This is DISPLAY
# ONLY now — it no longer gates scanning. Omit it and assets simply show no
# ASN/org. Bind-mount your local copy at /data/mmdb/.
mmdb_path: /data/mmdb/GeoLite2-ASN.mmdb

# Global politeness tier applied across ALL tools at once. One of:
#   paranoid / gentle  - low rates + small concurrency (avoid tripping WAFs)
#   normal             - the default; equals the per-tool defaults below
#   aggressive / insane - high rates / concurrency for lab targets you control
# Any explicit per-tool / concurrency value below OVERRIDES the profile.
throttle: normal

# Per-stage parallelism caps. All work is IO-bound, so high numbers are fine.
concurrency:
  default: 10        # generic fan-out
  llm: 4             # AI calls (LLMs are heavier; keep this lower)
  playwright: 5      # one browser context per slot — RAM-bound
  tls: 5             # parallel sslscan host scans

# Paths visited per live host during the Playwright crawl.
# Add more for deeper supply-chain coverage (each adds a navigation per host).
paths_per_host:
  - "/"

# OpenAI-compatible LLM endpoint. Tested with Ollama, llama.cpp server, vLLM, LM Studio.
llm:
  base_url: http://host.docker.internal:11434/v1
  api_key: ollama
  model: llama3.1:8b-instruct
  timeout_seconds: 120
  max_retries: 1

# AI behavior.
ai:
  # Context-aware profiling: before analysing headers/scripts, infer what each
  # app IS (login portal, API, marketing site, ...) and what controls it SHOULD
  # have, then calibrate findings to that. Adds one LLM call per host.
  # Set false to use the default context-light prompts (2 calls/host, no profile).
  profiling: true

# Per-tool config. Every tool accepts `extra_flags: []` for unsurfaced flags.
tools:
  subfinder:
    extra_flags: []

  dnsx:
    rate_limit: 1000    # DNS queries/sec (-rl). DNS is cheap; high default.
    extra_flags: []

  tlsx:
    rate_limit: 100     # cert-grab connections/sec (-rl). Touches target:443.
    extra_flags: []

  httpx:
    rate_limit: 100
    timeout: 10
    extra_flags: []

  nuclei:
    # Drop `info` for a clean signal floor. Add it back if you want full coverage.
    severities: [low, medium, high, critical]
    auto_scan: true       # use wappalyzer detection to limit templates to relevant tech
    rate_limit: 100
    timeout: 5
    user_agent: "WatchTower/0.1"
    extra_flags: []

  takeovers:
    # nuclei http/takeovers/ templates run against LIVE hosts with a third-party
    # CNAME; the dangling/NXDOMAIN class is matched deterministically (offline).
    severities: [high, critical]
    rate_limit: 50
    extra_flags: []

  sslscan:
    timeout: 300            # per-host outer timeout in seconds
    extra_flags: []

  playwright:
    wait_until: networkidle    # one of: load, domcontentloaded, networkidle, commit
    timeout_ms: 30000
    user_agent: null           # null = default Chromium UA
"""
