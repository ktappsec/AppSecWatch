"""Stage plugin architecture (DESIGN.md §6 evolution).

Each scanning step is a `Stage` subclass that owns its artifact location on
disk and how to run it.

The orchestrator (`watchtower.runner.run_scan`) builds a list of stages via
`watchtower.stages.pipeline.build_pipeline` and drives them uniformly. Adding a
new scanner = one new Stage class + (to make it selectable) one entry in the
`CAPABILITIES` registry in `capabilities.py`.
"""
from watchtower.stages.base import ParallelStage, Stage, execute_stages
from watchtower.stages.state import ScanState

__all__ = ["Stage", "ParallelStage", "ScanState", "execute_stages"]
