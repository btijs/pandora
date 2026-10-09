import logging

from angr import ExplorationTechnique

logger = logging.getLogger(__name__)


class SelfLoopBreaker(ExplorationTechnique):
    """
    Stops paths that are stuck on a branch to its own address (e.g., `b.n .` or `jmp .`), optionally preceded by nops
    (e.g., `1: nop; b.n 1b`).
    Such a state jumped back to the start of the block it just executed, and that block only contains nops and the branch.
    """

    def __init__(self, stash="self_loop"):
        super().__init__()
        self.stash = stash

    def _filter(self, s):
        if s.history.addr != s.addr or s.history.jumpkind != "Ijk_Boring":
            return False
        insns = s.block().capstone.insns
        if any(insn.mnemonic != "nop" for insn in insns[:-1]):
            return False
        logger.info(f"SelfLoopBreaker: stopping path stuck on branch to itself at {s.addr:#x}")
        return True

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        simgr.move(stash, self.stash, self._filter)
        return simgr
