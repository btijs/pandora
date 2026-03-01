from __future__ import annotations

import logging
from collections import defaultdict

import angr
import claripy
from angr.exploration_techniques import ExplorationTechnique

logger = logging.getLogger(name=__name__)


class HALMemoryCheckMerger(ExplorationTechnique):
    def __init__(self, project, wait_counter=10, prune=True):
        super().__init__()
        self.start_address = project.loader.find_symbol("tfm_hal_memory_check").rebased_addr
        self.merge_address = self.start_address + 12
        self.wait_counter_limit = wait_counter
        self.prune = prune
        self.stashes: dict[str, int] = {}  # stash name -> wait counter
        self.filter_marker = f"skip_next_filter_{self.merge_address:#x}"

    def mark_nofilter(self, simgr, stash):
        for state in simgr.stashes[stash]:
            state.globals[self.filter_marker] = True

    def mark_okfilter(self, simgr, stash):
        for state in simgr.stashes[stash]:
            state.globals.pop(self.filter_marker)

    def step(self, simgr, stash="active", **kwargs):
        for src_stash in self.stashes.keys():
            # ha ha, very funny, if this is being run on a single-step basis our filter probably misfired
            if len(simgr.stashes[src_stash]) == 1 and len(simgr.stashes[stash]) == 0:
                simgr = simgr.move(src_stash, stash)

        # perform all our analysis as a post-mortem on a given step
        stop_points = kwargs.pop("extra_stop_points", set())
        stop_points.add(self.merge_address)
        simgr = simgr.step(stash=stash, extra_stop_points=stop_points, **kwargs)

        # do filtering
        new_stash = []
        for state in simgr.stashes[stash]:
            if self.filter_marker not in state.globals and state.addr == self.merge_address:
                # Group states by return address and call history
                return_addr = state.callstack.ret_addr

                # Get addresses in history up to latest hit of self.start_address
                history_addrs = state.history.bbl_addrs
                last_index = next((i for i, addr in enumerate(reversed(history_addrs)) if addr == self.start_address), 0)
                history_hash = hash(tuple(history_addrs)[: -last_index - 1])

                stash_name = f"merge_waiting_{self.merge_address:#x}_ret_{return_addr:#x}_history_{history_hash:x}"

                self.stashes[stash_name] = 0
                simgr.stashes[stash_name].append(state)
            else:
                new_stash.append(state)
        simgr.stashes[stash][:] = new_stash

        for src_stash in self.stashes.keys():
            # nothing to do if there's no states waiting
            if len(simgr.stashes[src_stash]) == 0:
                continue

            # tick the counter
            self.stashes[src_stash] += 1

            # see if it's time to merge (out of active or hit the wait limit)
            if len(simgr.stashes[stash]) != 0 and self.stashes[src_stash] < self.wait_counter_limit:
                continue

            # only both merging if, you know, there's actually states to merge
            if len(simgr.stashes[src_stash]) == 1:
                simgr.move(src_stash, stash)
                continue

            # do the merge, keyed by unique callstack
            logger.info(f"Merging {len(simgr.stashes[src_stash])} states at {self.merge_address:#x}")

            # Merge states and add to active stash
            grouped_states = self.group_states_by_return_value(simgr.stashes[src_stash])
            for states in grouped_states.values():
                merged_state = self.merge_states_with_same_return(states)
                if merged_state is not None:
                    simgr.stashes[stash].append(merged_state)

            # Clear the waiting stash
            simgr.stashes[src_stash] = []

        # Clear empty stashes
        for src_stash in list(self.stashes.keys()):
            if len(simgr.stashes[src_stash]) == 0:
                del self.stashes[src_stash]
                del simgr.stashes[src_stash]

        return simgr

    def group_states_by_return_value(self, states):
        """
        Group states by their return value (r0) and address (lr).

        Args:
            states: List of states to group

        Returns:
            Dictionary mapping return values to lists of states
        """
        grouped: dict[int, list[angr.SimState]] = defaultdict(list)

        for state in states:
            ret_val = state.regs.r0

            # Try to get concrete return value
            if state.solver.symbolic(ret_val):
                logger.warning(f"State has symbolic return value: {ret_val}")
            else:
                ret_val = state.solver.eval(ret_val)

            grouped[ret_val].append(state)

        return grouped

    def merge_states_with_same_return(self, states: list[angr.SimState]) -> angr.SimState | None:
        """
        Merge multiple states into one with a symbolic return value.

        Args:
            states: List of states to merge
            return_reg: The register containing the return value (default: 'r0')

        Returns:
            A single merged state with symbolic return value and combined constraints
        """
        if not states:
            return None

        if len(states) == 1:
            return states[0]

        # Build the merged constraint: constraints1 || constraints2 || ...
        merged_constraint_parts = []

        for state in states:
            # Get all constraints from this state
            state_constraints = list(state.solver.constraints)

            if state_constraints:
                constraint = claripy.And(*state_constraints)
                merged_constraint_parts.append(constraint)

        # Combine all parts with OR
        merged_constraint = claripy.Or(*merged_constraint_parts)
        # merged_constraint = claripy.simplify(merged_constraint)

        # Clear existing constraints and add the merged one
        states[0].solver.reload_solver(merged_constraint)

        return states[0]
