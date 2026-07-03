import logging

import angr
import claripy
from angr import BP_AFTER, BP_BEFORE
from angr.sim_procedure import SimProcedure
from claripy import ast

from sdks.SAU_IDAU import ProcessorPrivilegeLevel, ProcessorSecurityState
from sdks.SDKManager import SDKManager
from ui.report import Reporter
from utilities.angr_helper import attacker_taint_regs
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
            attacker_taint_regs(self.state, SDKManager().get_safe_registers() + ["pc", "sp", "msp", "psp", "msplim", "psplim"])

            # Bit 0 of lr must be set to 0
            self.state.regs.lr = self.state.regs.lr & ~1

            self.state.history.previous_block_count = 0  # Reset block count to start path length measurement from the SG instruction, which is the actual secure entry point
            self.state.history.recent_block_count = 0  # Reset block count to start path length measurement from the SG instruction, which is the actual secure entry point
            self.state.globals["secure_init_finished"] = True

            self.state.globals["secure"] = True
            logger.info("State switched to secure mode.")
        else:
            logger.info("State is already in secure mode, ignoring SG instruction.")
            # Coming from secure world
            # Bit 0 of lr must be set to 1
            self.state.regs.lr = self.state.regs.lr | 1
        self.jump(self.state.addr + 4)


def nsc_fan_out(state):
    """
    Forks `state` into one new state per Non-Secure-Callable (NSC/SG) entry point, tainted
    and ready to resume execution from that entry point. Returns the list of new states
    (each with `.ip` already set to its NSC entry address); does not add them as angr
    successors, so callers outside of a SimProcedure's successor-adding context can reuse
    this too (e.g. to re-fan-out an enclave reentry state).
    """
    tainted_state = state.copy()

    attacker_taint_regs(tainted_state, SDKManager().get_safe_registers() + ["pc", "sp", "msp", "psp", "msplim", "psplim"])

    # Clear the history to make reporting less cluttered
    tainted_state.history.trim()

    sg_instr_addrs = tainted_state.globals.get("sg_instr_addrs", None)

    if sg_instr_addrs is None:
        raise ValueError("sg_instr_addrs global variable not set in state during SG successor setup.")

    logger.info(f"Possible sg instructions: {hexify(sg_instr_addrs)}, jumping to all of them in parallel (different states)")
    new_states = []
    for sg_addr in sg_instr_addrs:
        new_state = tainted_state.copy()
        new_state.globals["secure"] = False
        new_state.globals["just_entered_secure"] = True
        new_state.ip = sg_addr + 1
        new_states.append(new_state)
    return new_states


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
        if self.state.solver.satisfiable([jmp_addr & 1 == 0]):
            # lsb == 0 is possible
            # branch to non-secure state
            logger.info(f"{instr} with lsb == 0 branching to non-secure state at address {jmp_addr}.")
            self.handle_non_secure_jump(jmp_addr, l_flag)
        if self.state.solver.satisfiable([jmp_addr & 1 == 1]):
            # lsb == 1 is possible
            # branch to secure state, just jump to it like normal BX/BLX
            logger.info(f"{instr} with lsb == 1 branching to secure state at address {jmp_addr}.")
            self.handle_secure_jump(jmp_addr, l_flag)

    def add_sg_successors(self):
        for s in nsc_fan_out(self.state):
            self.successors.add_successor(s, s.ip, claripy.true(), "Ijk_Boring")

    def handle_secure_jump(self, jmp_addr, l_flag: bool):
        logger.info(f"Handling secure jump to address {jmp_addr} with lsb == 1.")
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
        logger.info(f"Handling non-secure jump to address {jmp_addr} with lsb == 0.")
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


class SimMemSet(SimProcedure):
    def run(self, dest, val, count, **kwargs):
        ret_addr = self.state.regs.lr - 0x4

        logger.info(f"Hooked memset at address {ret_addr}, dest: {dest}, val: {val}, count: {count}")

        # Get concrete values if possible
        # Try all regs separately
        try:
            dest = self.state.solver.eval_one(dest)
        except (angr.errors.SimUnsatError, angr.errors.SimValueError):
            pass

        try:
            count = self.state.solver.eval_one(count)
        except (angr.errors.SimUnsatError, angr.errors.SimValueError):
            count = self.state.solver.max_int(count)

        if isinstance(dest, int) and isinstance(val, int) and isinstance(count, int):
            logger.info(f"Performing concrete memset to address 0x{dest:x} with value 0x{val:x} for 0x{count:x} bytes.")
        else:
            logger.warning("One or more arguments to memset is symbolic, trying symbolic memset to address {dest} with value {val} for {count} bytes.")

        if isinstance(count, int) and count == 0:
            logger.info("Count is 0, skipping memset.")
        else:
            data = claripy.Concat(*([val] * count))
            self.state.memory.store(dest, data, max_size=count)

        # Return dest as per memset specification
        self.ret(dest)


def load_memory(state: angr.SimState, addr, size):
    data = state.memory.load(addr, size)

    logger.info(f"Data loaded: {data}")
    return data


def copy_memory(state: angr.SimState, dest, src, count):
    # In load memory, if the size is symbolic and too large, it will be concretized to some large number
    # However, this means the store will be done with this concretized size, which can result in false negatives.
    # To solve this, we first do the breakpoint generation check here for store
    # The `check_only` flag makes sure no actual store is performed, the store stops after the breakpoint generation
    # state.memory.store(dest, 0x0, size=count, check_only=True, with_enclave_boundaries=True)

    data = load_memory(state, src, count)
    if data.size() > 0x10000:
        logger.warning("Symbolic memory copy detected with large size, this may lead to false negatives.")
        # auto_embed()
    state.memory.store(dest, data, count)


class SimMemCpy(SimProcedure):
    def run(self, dest, src, count, **kwargs):
        ret_addr = self.state.regs.lr - 0x4

        logger.info(f"Hooked memcpy at address {ret_addr}, dest: {dest}, src: {src}, count: {count}")

        copy_memory(self.state, dest, src, count)

        # Return dest as per memcpy specification
        self.ret(dest)


class SimCopyFlashRegion(SimProcedure):
    def run(self, from_addr, to_add, size, **kwargs):
        ret_addr = self.state.regs.lr - 0x4

        logger.info(f"Hooked copy_flash_region at address {ret_addr}, from_addr: {from_addr}, to_addr: {to_add}, size: {size}")

        copy_memory(self.state, dest=to_add, src=from_addr, count=size)

        # Return 0 to indicate success
        self.ret(0)


class SimSkipFunction(SimProcedure):
    def run(self, function=None, **kwargs):
        logger.info(f"Skipping function {function.name if function else 'unknown'} at address 0x{self.state.addr:x}.")
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
            Reporter().report("SAU configuration write attempted after initial setup.", state, logger, "ptr", logging.CRITICAL)
            # logger.critical("SAU configuration write attempted after initial setup.")
            return
        address = state.solver.eval(state.inspect.mem_write_address)
        value = state.solver.eval(state.inspect.mem_write_expr)
        state.full_attribution_unit.sau.config_write(address, value)
