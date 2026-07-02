import copy
import logging
from dataclasses import dataclass

from angr import BP_AFTER, ExplorationTechnique

import ui
from sdks.SymbolManager import SymbolManager
from utilities.angr_helper import get_reg_value

logger = logging.getLogger(__name__)


@dataclass
class LoopInfo:
    symbol: str
    offset: int
    count: int
    most_recent: bool


class PandoraLoopSeer(ExplorationTechnique):
    """
    Attempts to break out of obvious infinite loops. Not smart but tries its best.
    """

    def __init__(self, bound: int = 100, deferred_stash="loops_deferred"):
        super().__init__()

        self.bound = bound
        self.deferred_stash = deferred_stash
        self.sm = SymbolManager()
        self.log_level = logging.INFO
        self.important_log_level = logging.CRITICAL

    def setup(self, simgr):
        for s in simgr.active:
            s.inspect.b("fork", when=BP_AFTER, action=self.clone_my_list)

    def clone_my_list(self, state):
        if "loop_stats" in state.globals:
            state.globals["loop_stats"] = copy.deepcopy(state.globals["loop_stats"])

    def step(self, simgr, **kwargs):
        """
        Before stepping, check whether the state has been in this loop for a while
        'This loop' refers to the last 2 encountered symbols
        """

        stuck_states = []
        for s in simgr.active:
            ip = get_reg_value(s, "ip")
            symbol, offset = self.sm.get_symbol(ip)

            """
            We keep two lists that each contain:
             - symbol name
             - offset
             - count
             - whether this list is the most recently added list (allows to easily swap their recentness)
            """
            if "loop_stats" in s.globals:
                loop_stats = s.globals["loop_stats"]
            else:
                loop_stats = [LoopInfo("", 0, 0, True), LoopInfo("", 0, 0, False)]

            # Go through the list and increment the symbol we are at
            latest = 0
            looped = False
            for idx, loopinfo in enumerate(loop_stats):
                if loopinfo.symbol == symbol and loopinfo.offset == offset:
                    # We have found our symbol, increment its count
                    looped = True
                    loop_stats[idx].count += 1
                    loop_stats[idx].most_recent = True

                    # Set the other most_recent flag to False
                    loop_stats[(idx + 1) % 2].most_recent = False

                    # Now, also do a check whether the combined count is over the maximum that we want
                    if loop_stats[0].count + loop_stats[1].count > self.bound:
                        stuck_states.append(s)
                        logger.log(self.log_level, f"Possibly stuck state {s} details: {ui.log_format.format_fields(s.globals['loop_stats'])}")

                        # Reset counts for states that are stuck
                        loop_stats[0].count = 0
                        loop_stats[1].count = 0

                if loopinfo.most_recent:
                    latest = idx

            if not looped:
                # symbol did not exist in our list

                # Swap out the not-most-recently-used one
                loop_stats[(latest + 1) % 2].symbol = symbol
                loop_stats[(latest + 1) % 2].offset = offset
                loop_stats[(latest + 1) % 2].count = 1
                loop_stats[(latest + 1) % 2].most_recent = True

                # And also swap latest again
                loop_stats[latest].most_recent = False

            # Update state
            s.globals["loop_stats"] = loop_stats

        if len(stuck_states) > 0:
            # Only move states if we have some to move AND we can also swap some back in.
            if len(simgr.active) + len(simgr.deferred) == len(stuck_states):
                if len(simgr.stashes[self.deferred_stash]) == 0:
                    return simgr.step(**kwargs)
                else:
                    # if we would empty active stash, attempt to move up to as many states back from stuck as we had in active
                    before_count = len(simgr.active)
                    diff = abs(before_count - len(stuck_states))
                    to_move = before_count - diff

                # Select the states to move
                move_stash = simgr.stashes[self.deferred_stash][:to_move]

                # Move the states
                simgr.move(from_stash=self.deferred_stash, to_stash="active", filter_func=lambda x: x in move_stash)

            # And move stuck states from active to stuck stash
            simgr.move(from_stash="active", to_stash=self.deferred_stash, filter_func=lambda x: x in stuck_states)

            logger.log(self.important_log_level, f"Deferred the following states as I believe they are stuck in a loop (stuck in same symbol for > {self.bound} steps): {stuck_states}")

        simgr = simgr.step(**kwargs)
        return simgr
