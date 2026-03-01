import logging

from angr.exploration_techniques import ExplorationTechnique

logger = logging.getLogger(name=__name__)


class RealSoftwareStatePruning(ExplorationTechnique):
    def __init__(self, pc_addrs_file):
        super().__init__()
        with open(pc_addrs_file, "r") as f:
            self.valid_pcs = [int(line.strip(), 16) for line in f]
        self.current_pc_index = 0
        self.start_addr = self.valid_pcs[0] if self.valid_pcs else None
        self.enabled = False

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        if self.current_pc_index >= len(self.valid_pcs):
            # If we've already exhausted the valid PCs, we can skip all pruning logic and just return the simgr as is.
            return simgr

        # Only start pruning once we hit the start address, if one was provided
        if not self.enabled:
            # Check if we should enable
            for state in simgr.stashes[stash]:
                if self.start_addr and state.addr == self.start_addr + 1:
                    self.enabled = True
                    logger.info(f"Enabling RealSoftwareStatePruning at address {state.addr:#x}")
                    break

        if not self.enabled:
            # If we're not enabled yet, just return the simgr without pruning
            return simgr

        # At the end of this step, we will always only have one state in the active stash.
        # To find the state we want to keep, we check the PC of each state against the valid PCs.
        # The one with the first occurrence in the file is the one we keep, and the rest are pruned.
        while True:
            if self.current_pc_index >= len(self.valid_pcs):
                # If we exhaust the valid PCs, we can stop pruning and keep all remaining states.
                logger.info("Exhausted valid PCs, stopping pruning and keeping all remaining states.")
                logger.info(f"Remaining states at addresses: {[hex(state.addr) for state in simgr.stashes[stash]]}")
                return simgr
            next_addr = self.valid_pcs[self.current_pc_index]
            for state in simgr.stashes[stash]:
                if state.addr == next_addr + 1:
                    logger.info(f"Keeping state at {state.addr:#x} and pruning {len(simgr.stashes[stash]) - 1} other states at {[hex(other_state.addr) for other_state in simgr.stashes[stash] if other_state != state]}")
                    simgr.stashes[stash] = [state]
                    return simgr
            self.current_pc_index += 1
