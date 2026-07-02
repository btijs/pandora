from __future__ import annotations

from angr.exploration_techniques.base import ExplorationTechnique


class LengthLimiter(ExplorationTechnique):
    """
    Length limiter on paths.
    """

    def __init__(self, max_length, drop=False):
        super().__init__()
        self._max_length = max_length
        self._drop = drop

    def _filter(self, s):
        return s.history.block_count > self._max_length and s.globals.get("secure_init_finished", False)

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        simgr.move("active", "_DROP" if self._drop else "cut", self._filter)
        return simgr
