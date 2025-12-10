import logging

import angr
import claripy
import IPython
from angr import BP_AFTER, BP_BEFORE
from angr.sim_procedure import SimProcedure
from claripy import ast

from explorer import taint
from sdks.SAU_IDAU import FullAttributionUnit, ProcessorPrivilegeLevel, ProcessorSecurityState
from ui.report import Reporter
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

        p = self.state.regs.__getattr__(rn)

        logger.info(f"Hooked TTA instruction at address 0x{self.state.addr:x},rd: {rd}, rn: {rn}={p}")

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


class SimBKPT(SimProcedure):
    def run(self, **kwargs):
        logger.info(f"Hooked BKPT instruction at address 0x{self.state.addr:x}.")
        self.exit(0)


class SimSG(SimProcedure):
    def run(self, **kwargs):
        logger.info(f"Hooked SG instruction at address 0x{self.state.addr:x}.")
        if "secure" not in self.state.globals:
            raise ValueError("State does not have 'secure' global variable set")
        elif not self.state.globals["secure"]:
            # Coming from non-secure world, switch to secure
            # Bit 0 of lr must be set to 0
            self.state.regs.lr = self.state.regs.lr & ~1

            # Clear the history, to make reporting less cluttered
            self.state.history.trim()
            self.state.globals["secure"] = True
            logger.info("State switched to secure mode.")
        else:
            logger.info("State is already in secure mode, ignoring SG instruction.")
            # Coming from secure world
            # Bit 0 of lr must be set to 1
            self.state.regs.lr = self.state.regs.lr | 1
            IPython.embed()
        self.jump(self.state.addr + 4)


class SimBXNS(SimProcedure):
    IS_FUNCTION = False

    def run(self, jmp_reg: str = "", l_flag: bool = False, **kwargs):
        instr = "BLXNS" if l_flag else "BXNS"
        logger.info(f"Hooked {instr} {jmp_reg} instruction at address 0x{self.state.addr:x}")

        jmp_addr = self.state.regs.__getattr__(jmp_reg)

        # ============================== EDIT SUCCESSORS (if needed) ==============================
        if not self.state.globals["sau_setup_done"]:
            # If the state was still in the setup phase, finish it now
            # And jump to all possible secure entry points in parallel

            self.state.globals["sau_setup_done"] = True
            logger.info("SAU setup finished.")

            tainted_state = self.state.copy()
            # Initialize all registers as being attacker tainted
            for reg_name in tainted_state.project.arch.register_names.values():
                if reg_name in ["pc", "cc_op", "cc_dep1", "itstate", "sp"]:
                    continue
                size = get_reg_size(tainted_state, reg_name)
                reg = taint.get_tainted_reg(tainted_state, reg_name, size * 8)
                set_reg_value(tainted_state, reg_name, reg)

            sg_instr_addrs = tainted_state.globals.get("sg_instr_addrs", [])

            logger.info(f"Possible sg instructions: {hexify(sg_instr_addrs)}, jumping to all of them in parallel (different states)")
            for sg_addr in sg_instr_addrs:
                # TODO: clear history
                new_state = tainted_state.copy()
                new_state.globals["secure"] = False
                self.successors.add_successor(new_state, sg_addr + 1, claripy.true(), "Ijk_Boring")

        # ================================== EDIT CURRENT STATE ===================================
        if self.state.solver.satisfiable([jmp_addr & 1 == 1]):
            # lsb == 1 is possible
            # branch to secure state, just jump to it
            logger.info(f"{instr} with lsb == 1 branching to secure state at address {jmp_addr}.")
            state1 = self.state.copy()
            state1.add_constraints((jmp_addr & 1) == 1)
            # TODO: check if this is correct
            self.successors.add_successor(state1, jmp_addr, claripy.true(), "Ijk_Call")

            # TODO: handle return for BLXNS instruction
        if self.state.solver.satisfiable([jmp_addr & 1 == 0]):
            # lsb == 0 is possible
            # branch to non-secure state
            state0 = self.state.copy()
            state0.add_constraints((jmp_addr & 1) == 0)

            # Call EEXIT BEFORE breakpoint of the original state
            self.state._inspect("eexit", BP_BEFORE)

            # Mark state as eexited
            self.state.globals["eexit"] = True
            if l_flag:
                # BLXNS instruction, so expected to return later
                # Saves return address and xPSR to secure stack
                # Sets LR to FNC_RETURN:
                #   0xFEFFFFFF (the function was called from the Secure state)
                #   0xFFFFFFFE (the function was called from the Non-secure state) (should not happen, see Definitive guide to ARM table 18.7)

                # When the NS code calls BX LR, the pc is set to FNC_RETURN, which then unstacks the return address and xPSR from the secure stack

                logger.info(f"{instr} with lsb == 0 branching to non-secure state at address {jmp_addr}, setting up for return later.")
                # TODO: implement non-secure return handling

                # Use new state0 for jumping
                self.successors.add_successor(state0, state0.addr + 2, claripy.true(), "Ijk_Boring")

            else:
                # BXNS instruction, so no return expected
                # TODO: check if it is still possible to return (e.g. by manually setting LR)
                logger.info(f"{instr} with lsb == 0 branching to non-secure state at address {jmp_addr}, no return expected.")
                # self.successors.add_successor(state0, jmp_addr, claripy.true(), "Ijk_Boring")
            # Lastly, call eexit breakpoint again (AFTER)
            self.state._inspect("eexit", BP_AFTER)


class SimBX(SimProcedure):
    def run(self, ret: str = "", l_flag: bool = False, **kwargs):
        instr = "BLX" if l_flag else "BX"
        logger.info(f"Hooked {instr} instruction at address 0x{self.state.addr:x}")

        curr_addr = self.state.addr

        ret_addr = self.state.regs.__getattr__(ret)

        try:
            lsb = self.state.solver.eval_one(ret_addr & 1)
        except (angr.errors.SimUnsatError, angr.errors.SimValueError):
            lsb = None
        if lsb == 0:
            # branch to non-secure state, raise HardFault/UsageFault
            logger.critical(f"{instr} {ret} => branching to non-secure state at address {ret_addr}, which is not allowed from secure state. Raising enclave fault.")
            self.state.globals["enclave_fault"] = True
        elif lsb == 1:
            # branch to secure state, just jump to it
            logger.info(f"{instr} {ret} => branching to secure state at address {ret_addr}")
            self.jump(ret_addr)
        else:
            # lsb can be either 0 or 1
            logger.info(f"{instr} {ret} => with symbolic lsb, branching to both secure and non-secure states.")
            # assume lsb == 0
            state0 = self.state.copy()
            state0.globals["enclave_fault"] = True
            self.successors.add_successor(state0, curr_addr, (ret_addr & 1) == 0, "Ijk_Call")

            # assume lsb == 1
            state1 = self.state.copy()
            self.successors.add_successor(state1, ret_addr, (ret_addr & 1) == 1, "Ijk_Call")


def setup_sau_hook(state):
    if state.solver.is_true(
        claripy.And(
            state.inspect.mem_write_address >= 0xE000EDD0,
            state.inspect.mem_write_address <= 0xE000EDD0 + 0x18,
        ),
    ):
        if "sau_setup_done" not in state.globals:
            raise RuntimeError("sau_setup_done not in state.globals during SAU setup hook.")
        elif state.globals["sau_setup_done"]:
            # TODO: fix reporting from the correct plugin. For now, I just use the ptr plugin.
            Reporter().report("SAU configuration write attempted after initial setup.", state, logger, "ptr", logging.CRITICAL, {})
            # logger.critical("SAU configuration write attempted after initial setup.")
            return
        address = state.solver.eval(state.inspect.mem_write_address)
        value = state.solver.eval(state.inspect.mem_write_expr)
        state.full_attribution_unit.sau.config_write(address, value)
