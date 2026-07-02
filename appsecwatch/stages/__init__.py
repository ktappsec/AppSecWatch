"""Stage plugin architecture (DESIGN.md §6 evolution).

Each scanning step is a `Stage` subclass that owns its artifact location on
disk and how to run it.

The orchestrator (`appsecwatch.runner.run_scan`) builds a list of stages via
`appsecwatch.stages.pipeline.build_pipeline` and drives them uniformly. Adding a
new scanner = one new Stage class + (to make it selectable) one entry in the
`CAPABILITIES` registry in `capabilities.py`.
"""
from appsecwatch.stages.base import ParallelStage, Stage, execute_stages
from appsecwatch.stages.state import ScanState

__all__ = ["Stage", "ParallelStage", "ScanState", "execute_stages"]
