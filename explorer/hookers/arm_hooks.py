import logging

import angr
import claripy
from angr import BP_AFTER, BP_BEFORE
from angr.sim_procedure import SimProcedure
from claripy import ast

from explorer import taint
from sdks.SAU_IDAU import ProcessorPrivilegeLevel, ProcessorSecurityState
from sdks.SDKManager import SDKManager
from ui.report import Reporter
from utilities.angr_helper import attacker_taint_regs, get_reg_size, set_reg_value
from utilities.helper import hexify

logger = logging.getLogger(__name__)


class SimTestTarget(SimProcedure):
    def run(
        self,
        rd: str = "",
        rn: str = "",
        a_flag: bool = False,
        t_flag: bool = False,
        **kwargs,
    ):
        attribution_unit = self.state.get_plugin("full_attribution_unit")
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
            ProcessorSecurityState.SECURE if self.state.globals.get("secure", True) else ProcessorSecurityState.NONSECURE,
            ProcessorPrivilegeLevel.PRIVILEGED,
            a_flag=a_flag,
            t_flag=t_flag,
        )

        self.state.regs.__setattr__(rd, res)

        self.jump(self.state.addr + 4)


class SimBKPT(SimProcedure):
    def run(self, **kwargs):
        logger.info(f"Hooked BKPT instruction at address 0x{self.state.addr:x}.")
        self.exit(-1)


class SimSG(SimProcedure):
    def run(self, **kwargs):
        logger.info(f"Hooked SG instruction at address 0x{self.state.addr:x}.")
        if "secure" not in self.state.globals:
            raise ValueError("State does not have 'secure' global variable set")
        elif not self.state.globals["secure"]:
            # Coming from non-secure world, switch to secure
            # Bit 0 of lr must be set to 0
            self.state.regs.lr = self.state.regs.lr & ~1

            self.state.globals["secure"] = True
            logger.info("State switched to secure mode.")
        else:
            logger.info("State is already in secure mode, ignoring SG instruction.")
            # Coming from secure world
            # Bit 0 of lr must be set to 1
            self.state.regs.lr = self.state.regs.lr | 1
        self.jump(self.state.addr + 4)


class SimBXNS(SimProcedure):
    IS_FUNCTION = False

    def run(self, jmp_reg: str = "", l_flag: bool = False, **kwargs):
        instr = "BLXNS" if l_flag else "BXNS"
        logger.info(f"Hooked {instr} {jmp_reg} instruction at address 0x{self.state.addr:x}")

        jmp_addr = self.state.regs.__getattr__(jmp_reg)

        # ============================== Get SG Successors ==============================
        if not self.state.globals["sau_setup_done"]:
            # If the state was still in the setup phase, finish it now
            self.state.globals["sau_setup_done"] = True
            logger.info("SAU setup finished.")

            # And jump to all possible secure entry points in parallel
            self.add_sg_successors()

        # ===================== Set eexit and continuing states =========================
        if self.state.solver.satisfiable([jmp_addr & 1 == 1]):
            # lsb == 1 is possible
            # branch to secure state, just jump to it like normal BX/BLX
            logger.info(f"{instr} with lsb == 1 branching to secure state at address {jmp_addr}.")
            self.handle_secure_jump(jmp_addr, l_flag)
        if self.state.solver.satisfiable([jmp_addr & 1 == 0]):
            # lsb == 0 is possible
            # branch to non-secure state
            logger.info(f"{instr} with lsb == 0 branching to non-secure state at address {jmp_addr}.")
            self.handle_non_secure_jump(jmp_addr, l_flag)

    def add_sg_successors(self):
        tainted_state = self.state.copy()

        attacker_taint_regs(tainted_state, SDKManager().get_safe_registers() + ["pc", "sp", "msp", "psp", "msplim", "psplim"])

        # Clear the history to make reporting less cluttered
        tainted_state.history.trim()

        sg_instr_addrs = tainted_state.globals.get("sg_instr_addrs", None)

        if sg_instr_addrs is None:
            raise ValueError("sg_instr_addrs global variable not set in state during SG successor setup.")

        logger.info(f"Possible sg instructions: {hexify(sg_instr_addrs)}, jumping to all of them in parallel (different states)")
        for sg_addr in sg_instr_addrs:
            new_state = tainted_state.copy()
            new_state.globals["secure"] = False
            self.successors.add_successor(new_state, sg_addr + 1, claripy.true(), "Ijk_Boring")

    def handle_secure_jump(self, jmp_addr, l_flag: bool):
        new_state = self.state.copy()
        new_state.add_constraints((jmp_addr & 1) == 1)

        actual_jmp_addr = jmp_addr | 1  # lsb set to 1 for actual jump

        # Set constraint that jump address is inside secure memory region
        # Otherwise, a HardFault would be raised on real hardware
        secure_ranges = SDKManager().get_enclave_range()  # S and NSC
        new_state.add_constraints(claripy.Or(*[claripy.And(actual_jmp_addr >= start, actual_jmp_addr <= end) for (start, end) in secure_ranges]))

        if not new_state.solver.satisfiable():
            logger.warning(f"Secure jump to address {jmp_addr} is not satisfiable under current constraints, skipping.")
            return

        if l_flag:
            # BLXNS instruction, so store return address in LR
            return_addr = self.state.addr + 2  # address of next instruction after BLXNS (2 bytes)
            new_state.regs.lr = return_addr | 1

        self.successors.add_successor(new_state, actual_jmp_addr, claripy.true(), "Ijk_Call")

    def handle_non_secure_jump(self, jmp_addr, l_flag: bool):
        continuing_state = self.state.copy()
        continuing_state.add_constraints((jmp_addr & 1) == 0)

        actual_jmp_addr = jmp_addr | 1  # lsb set to 1 for actual jump

        # Set constraint that jump address is outside secure memory region
        # Otherwise, a HardFault would be raised on real hardware
        secure_ranges = SDKManager().get_enclave_range()  # S and NSC
        continuing_state.add_constraints(claripy.And(*[claripy.Or(actual_jmp_addr < start, actual_jmp_addr > end) for (start, end) in secure_ranges]))

        if not continuing_state.solver.satisfiable():
            logger.warning(f"Non-secure jump to address {jmp_addr} is not satisfiable under current constraints, skipping.")
            return

        eexiting_state = continuing_state.copy()

        # Call EEXIT BEFORE breakpoint of the eexiting state
        eexiting_state._inspect("eexit", BP_BEFORE)

        # Mark state as eexited
        eexiting_state.globals["eexit"] = True
        if l_flag:
            # BLXNS instruction, so expected to return later
            # Saves return address and xPSR to secure stack
            # Sets LR to FNC_RETURN:
            #   0xFEFFFFFF (the function was called from the Secure state)
            #   0xFFFFFFFE (the function was called from the Non-secure state) (should not happen, see Definitive guide to ARM table 18.7)

            # When the NS code calls BX LR, the pc is set to FNC_RETURN, which then unstacks the return address and xPSR from the secure stack
            return_addr = self.state.addr + 2  # address of next instruction after BLXNS (2 bytes)

            # Use continuing_state as returning state
            self.successors.add_successor(continuing_state, return_addr, claripy.true(), "Ijk_Boring")

            # Use eexiting_state as jumping/eexiting state
            eexiting_state.regs.lr = 0xFFFFFFFE
            eexiting_state.stack_push(return_addr)
        else:
            # BXNS instruction, so no return expected
            # TODO: check if it is still possible to return (e.g. by manually setting LR)
            pass

        # Should jump to actual_jmp_addr, but this gives an angr error
        # Since it won't actually continue executing from there, we just set the jump to the current address
        # This is to make sure it is picked up by Pandora as an exiting state
        self.successors.add_successor(eexiting_state, self.state.addr, claripy.true(), "Ijk_Call")

        # Lastly, call eexit breakpoint again (AFTER)
        eexiting_state._inspect("eexit", BP_AFTER)


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


class SimSkipFunction(SimProcedure):
    def run(self, function="", **kwargs):
        logger.info(f"Skipping function {function if function else 'unknown'} at address 0x{self.state.addr:x}.")
        self.ret(0)


class SimSVC(SimProcedure):
    def run(self, bytes_to_skip=2, opstr="", svc_num=0, **kwargs):
        logger.info(f"Hooked `svc {opstr}` at address 0x{self.state.addr:x}. Skipping...")

        # Skip and return 0 (success)
        self.state.regs.r0 = 0
        self.jump(self.state.addr + bytes_to_skip)

        # svc_handler = self.project.loader.find_symbol("SVC_Handler")
        # if svc_handler is None:
        #     logger.critical("SVC_Handler not found in binary, cannot handle SVC instruction. Exiting.")
        #     return self.exit(1)

        # set_reg_value(self.state, "control", 0)
        # set_reg_value(self.state, "cpsr", self.state.regs.cpsr | 0xb) # Set exception number to SVC (11)
        # set_reg_value(self.state, "lr", 0xFFFFFFFD)

        # self.jump(svc_handler.rebased_addr, "Ijk_Boring")


class SimLaunchNS(SimProcedure):
    IS_FUNCTION = False

    def run(self, **kwargs):
        logger.info(f"Hooked launch NS instruction at address 0x{self.state.addr:x}")

        # ============================== Get SG Successors ==============================
        if not self.state.globals["sau_setup_done"]:
            # If the state was still in the setup phase, finish it now
            self.state.globals["sau_setup_done"] = True
            logger.info("SAU setup finished.")

            # Seal stack
            self.state.stack_push(0xDEADBEEF)
            self.state.stack_push(0xFEF5EDA5)

            # And jump to all possible secure entry points in parallel
            self.add_sg_successors()

    def add_sg_successors(self):
        tainted_state = self.state.copy()
        # Initialize all registers as being attacker tainted
        for reg_name in tainted_state.project.arch.register_names.values():
            if reg_name in ["pc", "cc_op", "cc_dep1", "itstate", "sp"]:
                continue
            size = get_reg_size(tainted_state, reg_name)
            reg = taint.get_tainted_reg(tainted_state, reg_name, size * 8)
            set_reg_value(tainted_state, reg_name, reg)

        # Clear the history to make reporting less cluttered
        tainted_state.history.trim()

        sg_instr_addrs = tainted_state.globals.get("sg_instr_addrs", None)

        if sg_instr_addrs is None:
            raise ValueError("sg_instr_addrs global variable not set in state during SG successor setup.")

        logger.info(f"Possible sg instructions: {hexify(sg_instr_addrs)}, jumping to all of them in parallel (different states)")
        for sg_addr in sg_instr_addrs:
            new_state = tainted_state.copy()
            new_state.globals["secure"] = False
            self.successors.add_successor(new_state, sg_addr + 1, claripy.true(), "Ijk_Boring")


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
