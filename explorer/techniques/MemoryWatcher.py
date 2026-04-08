from __future__ import annotations

import gc
import logging

import claripy
import psutil
import z3
from angr.exploration_techniques.base import ExplorationTechnique
from claripy.backends.backend_z3 import BackendZ3

from utilities.helper import auto_embed

logger = logging.getLogger(name=__name__)


class MemoryWatcher(ExplorationTechnique):
    """Memory Watcher

    Args:
        min_memory (int,optional): Minimum amount of free memory in MB before
                    stopping execution

    At each step, keep an eye on how much memory is left on the system. Drop
    off states to effectively stop execution if we're below a given threshold.
    """

    def __init__(self, min_memory):
        super().__init__()
        self.min_memory = min_memory * 1024 * 1024
        # Z3 can use 90% of max memory
        self.max_z3_memory = (psutil.virtual_memory().total - self.min_memory) * 0.9

    def step(self, simgr, stash="active", **kwargs):
        z3_usage = z3.Z3_get_estimated_alloc_size()
        available = psutil.virtual_memory().available

        logger.info(f"{available / (1024**3):.2f} GB available, Z3: {z3_usage / (1024**3):.2f} GB")

        if z3_usage > self.max_z3_memory or available <= self.min_memory:
            self.reset_memory(simgr, stash)

        available = psutil.virtual_memory().available
        if available <= self.min_memory:
            logger.info(f"Low memory detected ({available / (1024**3):.2f} GB available), dropping states")
            for state in simgr.stashes[stash]:
                del state
            simgr.stashes[stash] = []
            gc.collect()

        return simgr.step(stash=stash, **kwargs)

    def reset_memory(self, simgr, stash):
        before_mem = psutil.virtual_memory().available
        before_z3 = z3.Z3_get_estimated_alloc_size()
        z3.Z3_reset_memory()
        claripy.backends.z3 = BackendZ3()
        claripy.backends.z3.downsize()

        # Reload states against the new context
        for state in simgr.stashes[stash]:
            state.solver.reload_solver()

        # Delete eexited states to free up memory
        for state in simgr.stashes["eexited"]:
            del state
        simgr.stashes["eexited"] = []

        gc.collect()

        after_mem = psutil.virtual_memory().available
        after_z3 = z3.Z3_get_estimated_alloc_size()
        logger.info(f"Memory reset: {before_mem / (1024**3):.2f} GB -> {after_mem / (1024**3):.2f} GB, Z3: {before_z3 / (1024**3):.2f} GB -> {after_z3 / (1024**3):.2f} GB")

        auto_embed()
