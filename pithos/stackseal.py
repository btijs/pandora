import logging

import angr
import archinfo
import claripy

from pithos.BasePlugin import BasePlugin
from sdks.SDKManager import SDKManager
from ui.action import UserActionWithLevel
from ui.report import Reporter
from utilities.angr_helper import concretize_value_or_none, get_reg_value

logger = logging.getLogger(__name__)

# Global variables used by the hooks.
taint_action = UserActionWithLevel()
seal_shortname = "seal"


class StackSealPlugin(BasePlugin):
    """
    Plugin for checking if the stack is sealed.

    https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Armv8-M%20Architecture-Stack%20sealing%20and%20why%20it%20is%20needed%20in%20TrustZone%20for%20Armv8-M.pdf

    """

    def __init__(self, init_state, reporter, usr_act=UserActionWithLevel(), shortname=seal_shortname):
        self.angr_arch = SDKManager().get_angr_arch()
        super().__init__(init_state, reporter, usr_act, shortname)

        if self.angr_arch == "ARMCortexM":
            pass
        else:
            logger.warning("StackSealPlugin is only implemented for ARMCortexM, skipping plugin initialization.")

    @staticmethod
    def get_help_text():
        return "Validates that the stack is sealed (only for Arm Cortex-M)."

    def init_globals(self):
        global taint_action, seal_shortname
        taint_action = self.action
        seal_shortname = self.shortname

    def init_angr_breakpoints(self, init_state):
        """ """
        if self.angr_arch == "ARMCortexM":
            init_state.inspect.b("eexit", when=angr.BP_AFTER, action=check_stack_correctly_sealed)
            # TODO: NS can have interrupts too, so it should also be sealed then.


def check_stack_correctly_sealed(state):
    sp_to_seal = get_sp_to_seal(state)

    sp_value = get_reg_value(state, sp_to_seal)
    sp_value = concretize_value_or_none(state, sp_value)
    if sp_value is None:
        info = f"Could not concretize {sp_to_seal} value, skipping stack sealing check."
        logger.warning(info)
        return Reporter().report(info, state, logger, seal_shortname, logging.WARNING)

    if not is_sealed(state, sp_value):
        info = f"Stack is not sealed at {sp_to_seal.upper()} value {hex(sp_value)}"
        Reporter().report(info, state, logger, seal_shortname, logging.WARNING)
        taint_action(state=state, info=info, level=logging.WARNING)
    else:
        logger.info(f"Stack is correctly sealed at {sp_to_seal.upper()} value {hex(sp_value)}")


def get_sp_to_seal(state) -> str:
    xpsr = get_reg_value(state, "cpsr")  # xpsr is called cpsr in angr
    xpsr = concretize_value_or_none(state, xpsr)
    if xpsr is None:
        info = "Could not concretize xPSR, skipping stack sealing check."
        logger.warning(info)
        return Reporter().report(info, state, logger, seal_shortname, logging.WARNING)

    if (xpsr & 0x1FF) != 0:
        # If IPSR != 0, we are in handler mode
        # In handler mode, MSP is used, so PSP should be sealed
        return "psp"
    else:
        # If IPSR == 0, we are in thread mode
        # In thread mode, CONTROL[1] determines whether MSP or PSP is used
        control = get_reg_value(state, "control")
        control = concretize_value_or_none(state, control)
        if control is None:
            info = "Could not concretize CONTROL register, skipping stack sealing check."
            logger.warning(info)
            return Reporter().report(info, state, logger, seal_shortname, logging.WARNING)

        if (control & 0b10) == 0:
            # If CONTROL[1] == 0, MSP is used, so PSP should be sealed
            return "psp"
        else:
            # If CONTROL[1] == 1, PSP is used, so MSP should be sealed
            return "msp"


def is_sealed(state, sp_value):
    # Load the value at the stack pointer and check if it matches the sealing value (0xFEF5EDA5)
    expected_sealing_value = 0xFEF5EDA5
    real_sealing_value = state.memory.load(claripy.BVV(sp_value, state.arch.bits), 4, disable_actions=True, inspect=False, endness=archinfo.Endness.LE)
    real_sealing_value = concretize_value_or_none(state, real_sealing_value)
    return real_sealing_value == expected_sealing_value
