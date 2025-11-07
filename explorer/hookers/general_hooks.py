import logging

from angr import SimProcedure

import ui

logger = logging.getLogger(__name__)


class SimNop(SimProcedure):
    IS_FUNCTION = False
    NEEDS_ENDBR = False

    def run(self, opstr="", bytes_to_skip=3, mnemonic="", **kwargs):
        logger.info(f"skipping over {bytes_to_skip}-byte instruction {ui.log_format.format_inline_header(f'{mnemonic} {opstr}')} at {self.state.addr:#x}")
        self.state.globals["prev_skipped_inst"] = {"opcode": mnemonic, "addr": self.state.addr, "len": bytes_to_skip, "opstr": opstr}

        self.jump(self.state.addr + bytes_to_skip)
