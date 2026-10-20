import json
import logging
import time
from pathlib import Path

import angr
from angr import ExplorationTechnique

from explorer.enclave import eenter
from sdks.SDKManager import SDKManager
from ui.action import UserActionWithLevel
from ui.log_format import log_always
from ui.report import generate_basedir
from utilities.angr_helper import get_reg_value

logger = logging.getLogger(__name__)

STACK_REGS = ["sp", "msp", "psp", "msp_s", "psp_s"]

# The dead part of the stack below the stack pointer that is ignored by the fingerprint is at most this large
DEAD_STACK_WINDOW = 0x10000


class EnclaveReentry(ExplorationTechnique):
    """
    Performs the reentry of the enclave for states that are marked as eexited AND are unique.
    """

    def __init__(self, enclave_reentry_count: int, init_state: angr.SimState, unique_state_list: set, user_action: UserActionWithLevel):
        super().__init__()

        self.enclave_reentry_count = enclave_reentry_count
        self.initial_state = init_state
        self.performed_reentries = 0
        # Timing of the reentry rounds (round 0 is the initial entry)
        self.start_time = time.time()
        self.round_start_time = self.start_time
        self.round_steps = 0
        self.unique_states = unique_state_list
        self.action = user_action
        self.secure_ranges = SDKManager().get_enclave_range()
        # Allocated ELF sections that hold data, i.e. everything a stack pointer must never be allowed to hide
        self.data_sections = [(sec.vaddr, sec.vaddr + sec.memsize) for sec in init_state.project.loader.main_object.sections if sec.occupies_memory and sec.memsize > 0 and "stack" not in sec.name.lower()]
        # Fingerprints of all states that were (or are waiting to be) entered, over all rounds
        self.seen_fingerprints = {self._fingerprint(init_state)[0]} if enclave_reentry_count > 0 else set()
        self.round_exits = 0
        self.round_new = 0
        self.diag_file = None

    def setup(self, simgr):
        if self.enclave_reentry_count > 0:
            binpath = Path(self.initial_state.project.filename)
            self.diag_file = open(generate_basedir("report_folder", binpath) / f"reentry_states_{binpath.stem}.jsonl", "w")

    def _dead_stack(self, state):
        """
        Returns the [start, end) range below the stack pointer of `state` whose contents are dead once the secure world
        exits, or None. The range never extends into an ELF data section, and the rule is skipped altogether when the
        stack pointer itself points into one (e.g. a thread stack allocated on the heap), since memory below it is live.
        """
        sp = get_reg_value(state, "sp")
        if not isinstance(sp, int) or not any(start <= sp <= end for start, end in self.secure_ranges):
            return None
        if any(start <= sp < end for start, end in self.data_sections):
            return None
        low = max([sp - DEAD_STACK_WINDOW] + [end for _, end in self.data_sections if end <= sp])
        return low, sp

    def _secure_runs(self, state):
        """
        Returns the contiguous (start, length) runs of secure memory in which `state` differs from the initial state.
        Non-secure memory is never stored to (and every non-secure load returns fresh attacker data), so secure memory
        is all the state that carries over from one entry to the next. The dead stack below the stack pointer is left out.
        """
        changed = state.memory.changed_bytes(self.initial_state.memory) | self.initial_state.memory.changed_bytes(state.memory)
        dead = self._dead_stack(state)
        changed = sorted(a for a in changed if any(start <= a <= end for start, end in self.secure_ranges) and not (dead and dead[0] <= a < dead[1]))

        runs = []
        for addr in changed:
            if runs and runs[-1][0] + runs[-1][1] == addr:
                runs[-1][1] += 1
            else:
                runs.append([addr, 1])
        return [tuple(r) for r in runs]

    def _fingerprint(self, state):
        """
        Fingerprint of the secure memory of `state`, insensitive to the names of symbolic variables: every entry taints
        the registers and non-secure inputs with fresh variables, so states that are equal up to renaming would otherwise
        never match. Path constraints are not part of the fingerprint.
        """
        mem_state = state.copy()  # loads of uninitialized memory may fill it, keep the real state untouched
        var_map, counter = {}, 0
        parts = []
        for start, length in self._secure_runs(state):
            val = mem_state.memory.load(start, length, inspect=False, disable_actions=True, with_enclave_boundaries=False)
            var_map, counter, canonical = val.canonicalize(var_map, counter)
            parts.append((start, length, canonical.hash()))
        return hash(tuple(parts)), parts

    def _log_diagnostics(self, state, fingerprint, parts, is_new):
        if self.diag_file is None:
            return
        entry = {
            "round": self.performed_reentries,
            "time": time.time(),
            "fingerprint": fingerprint,
            "new": is_new,
            "ip": state.addr,
            "stack_regs": {r: str(get_reg_value(state, r)) for r in STACK_REGS},
            "runs": [[start, length, h] for start, length, h in parts],
        }
        self.diag_file.write(json.dumps(entry) + "\n")
        self.diag_file.flush()

    def finish(self):
        now = time.time()
        log_always(
            logger,
            f"--- Reentry round {self.performed_reentries} ended with the run: took {now - self.round_start_time:.1f}s and {self.round_steps} steps (elapsed {now - self.start_time:.1f}s, {self.performed_reentries} reentries performed).",
        )

    def step(self, simgr, **kwargs):
        simgr = simgr.step(**kwargs)
        self.round_steps += 1

        """
        After stepping, remove the eexited stash by putting all eexited states either into the new_uniques stash
        or by dropping them if they are not unique
        """
        if self.enclave_reentry_count > 0 and len(simgr.stashes["eexited"]) > 0:
            new_count = 0
            for s in simgr.stashes["eexited"]:
                fingerprint, parts = self._fingerprint(s)
                is_new_unique = fingerprint not in self.seen_fingerprints
                self._log_diagnostics(s, fingerprint, parts, is_new_unique)

                if is_new_unique:
                    new_count += 1
                    self.seen_fingerprints.add(fingerprint)
                    simgr.move(from_stash="eexited", to_stash="new_uniques", filter_func=lambda x: x is s)

            self.round_exits += len(simgr.stashes["eexited"]) + new_count
            self.round_new += new_count

            # Clean up eexit stash after removing uniques
            logger.info(f"Cleaned up {len(simgr.stashes['eexited'])} eexited states, we got {new_count} new uniques for a total of {len(simgr.stashes['new_uniques'])} new uniques and {len(self.seen_fingerprints)} unique states seen")
            simgr.drop(stash="eexited")
            simgr._copy_stashes()

        """
        After stepping, our active stash may be empty so we check whether we may want to reenter some of the states
        """
        states_exhausted = len(simgr.active) == 0
        if states_exhausted and self.performed_reentries < self.enclave_reentry_count and len(simgr.stashes["new_uniques"]) > 0:
            now = time.time()
            log_always(
                logger,
                f"--- Reentry round {self.performed_reentries} done: took {now - self.round_start_time:.1f}s and {self.round_steps} steps, {self.round_exits} exits of which {self.round_new} new unique states ({len(self.seen_fingerprints)} seen in total) (elapsed {now - self.start_time:.1f}s, unix time {now:.0f}).",
            )
            self.performed_reentries += 1
            self.round_start_time = now
            self.round_steps = 0
            self.round_exits = 0
            self.round_new = 0
            log_always(logger, f"--- Exhausted all my states. Restarting all {len(simgr.stashes['new_uniques'])} new unique states for reentry round {self.performed_reentries}...")

            reentered_states = []
            for state in simgr.stashes["new_uniques"]:
                eenter(state)
                state.globals["reentry_round"] = self.performed_reentries
                # SDK-specific fan-out (no-op for single-entry-point SDKs like SGX;
                # re-enters all NSC functions in parallel for ARM Cortex-M)
                reentered_states.extend(SDKManager().get_reentry_fanout(state))

            # restart all new unique states (the ones that we did not restart)
            simgr.drop(stash="new_uniques")
            simgr.populate("active", reentered_states)

            # new_uniques = get_unique_states(simgr.stashes['eexited'], self.initial_state, existing_uniques=simgr.stashes['uniques'])
            # logger.debug(f'Found {len(new_uniques)} unique states.')
            # if len(new_uniques) > 0:
            #     logger.debug(f'Their diffs:\n{ui.log_format.format_fields(get_mem_diffs(list(new_uniques), self.initial_state))}')
            #
            #     # Call eenter on all unique states that we did not encounter yet
            #     logger.info(f' --- Preparing {len(new_uniques)} states for reentry...')
            #     for state in new_uniques:
            #         eenter(state)
            #
            #     # Add the new uniques to the existing unique list
            #     self.unique_states.update(new_uniques)
            #     logger.info(f'Set of unique states now has a size of {len(self.unique_states)} to reduce state set for next round.')
            #
            #     # And move those states that are now restored back to the active stash (i.e. the unique states)
            #     simgr.move(from_stash='eexited', to_stash='active',
            #                     filter_func=lambda s: s.globals['eexit'] is False)
            #
            #     logger.info(f'successors of {len(new_uniques)} unique states have moved to the '
            #                  f'active states (now size {len(simgr.active)}).')
            #
            # else:
            #     logger.info('Doing nothing. Not reentering enclave, we are done.')

            log_always(logger, f"--- Done with this reentry. Active stash now has size {len(simgr.active)}")

            self.action(state={"active": simgr.active, "init_state": self.initial_state}, info="[enclave reentry]")

        return simgr
