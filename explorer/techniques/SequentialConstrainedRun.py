from __future__ import annotations

import logging

from angr.exploration_techniques import ExplorationTechnique

logger = logging.getLogger(name=__name__)


class SequentialConstrainedRun(ExplorationTechnique):
    def __init__(self):
        super().__init__()
        self.waiting_stash = "waiting_for_teeentry"
        self.max_steps = 500

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash, **kwargs)

        # Increment num_steps for states in the active stash
        for state in simgr.stashes[stash]:
            if state.globals.get("num_steps") is not None:
                state.globals["num_steps"] += 1

        # Stash states that have exceeded max_steps
        stash_len_before = len(simgr.stashes[stash])
        simgr.drop(stash=stash, filter_func=lambda s: s.globals.get("num_steps", 0) > self.max_steps)
        stash_len_after = len(simgr.stashes[stash])
        if stash_len_before != stash_len_after:
            logger.info(f"Dropped {stash_len_before - stash_len_after} states due to num_steps > {self.max_steps}")

        # If there are no active states but there are waiting states, move one back to active
        if len(simgr.stashes[stash]) == 0 and len(simgr.stashes[self.waiting_stash]) > 0:
            moved_state = simgr.stashes[self.waiting_stash].pop()
            simgr.stashes[stash].append(moved_state)
            if moved_state.globals.get("tfm_group") and moved_state.globals.get("tfm_function"):
                logger.info(f"Resuming TFM function {moved_state.globals['tfm_group']}::{moved_state.globals['tfm_function']} after waiting")
            logger.info(f"Moved 1 state from '{self.waiting_stash}' to '{stash}': {moved_state}")

        return simgr

    def filter(self, simgr, state, **kwargs):
        if state.globals.get("just_entered_secure", False):
            state.globals.pop("just_entered_secure")
            state.globals["num_steps"] = 0
            return self.waiting_stash
        return simgr.filter(state, **kwargs)
