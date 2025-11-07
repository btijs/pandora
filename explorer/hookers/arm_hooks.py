import logging

import claripy
from angr.sim_procedure import SimProcedure
from claripy import ast

from explorer import taint
from sdks.SAU_IDAU import FullAttributionUnit, ProcessorPrivilegeLevel, ProcessorSecurityState
from utilities.angr_helper import get_reg_size, set_reg_value
from utilities.helper import hexify

logger = logging.getLogger(__name__)


class SimTestTarget(SimProcedure):
    def run(
        self,
        rd: str = "",
        rn: str = "",
        a_flag: bool = False,
        t_flag: bool = False,
        attribution_unit: FullAttributionUnit | None = None,
        **kwargs,
    ):
        if attribution_unit is None:
            raise ValueError("Attribution unit must be provided to TestTarget SimProcedure")
        if not rd or not rn:
            raise ValueError("rd and rn must be provided to TestTarget SimProcedure")

        print(
            f"Hooked TTA instruction at address 0x{self.state.addr:x},rd: {rd}, rn: {rn}={self.state.regs.__getattr__(rn)}",
        )

        p = self.state.regs.__getattr__(rd)
        if not isinstance(p, ast.BV):
            raise TypeError("TTA instruction address must be a bitvector")

        res = attribution_unit.get_tt_response(
            p,
            ProcessorSecurityState.SECURE,  # TODO: for now, we only execute secure code
            ProcessorPrivilegeLevel.PRIVILEGED,  # TODO: implement when MPU is added
            a_flag=a_flag,
            t_flag=t_flag,
        )

        self.state.regs.__setattr__(rd, res)

        self.jump(self.state.addr + 4)


class SimSG(SimProcedure):
    def run(self, **kwargs):
        logger.warning(f"Hooked SG instruction at address 0x{self.state.addr:x}, SKIPPING (NOT IMPLEMENTED)")
        self.jump(self.state.addr + 4)


class SimBXNS(SimProcedure):
    def run(self, **kwargs):
        logger.info(f"Hooked B{{L}}XNS instruction at address 0x{self.state.addr:x}")
        if not self.state.globals["sau_setup_done"]:
            self.state.globals["sau_setup_done"] = True
            logger.info("SAU setup finished.")

            # Initialize all registers as being attacker tainted
            for reg_name in self.state.project.arch.register_names.values():
                if reg_name in ["pc", "cc_op", "cc_dep1", "itstate", "sp"]:
                    continue
                size = get_reg_size(self.state, reg_name)
                reg = taint.get_tainted_reg(self.state, reg_name, size * 8)
                set_reg_value(self.state, reg_name, reg)

            sg_instr_addrs = self.state.globals.get("sg_instr_addrs", [])

            logger.info(f"Possible sg instructions: {hexify(sg_instr_addrs)}, jumping to all of them in parallel (different states)")
            for sg_addr in sg_instr_addrs:
                new_state = self.state.copy()
                self.successors.add_successor(new_state, sg_addr + 1, claripy.true(), "Ijk_Boring")
            self.ret()

        self.exit(0)
