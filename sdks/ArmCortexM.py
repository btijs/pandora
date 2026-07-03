import logging
import os

import angr
import claripy
from claripy import UninitializedAnnotation

from explorer.taint import AttackerTaintConservative
from sdks.AbstractSDK import AbstractSDK
from sdks.SAU_IDAU import IDAU, SAU, FullAttributionUnit
from ui import console
from utilities.angr_helper import set_reg_value

logger = logging.getLogger(__name__)


class ArmCortexM(AbstractSDK):
    def __init__(self, elffile, init_state, version_str, idau_json_file=None, **kwargs):
        super().__init__(elffile, init_state, version_str, **kwargs)

        console.print(f"Elf file: {elffile}")
        console.print(f"Init state: {init_state}")
        console.print(f"Version string: {version_str}")
        console.print(f"IDAU JSON file: {idau_json_file}")
        console.print(f"Additional kwargs: {kwargs}")

        if idau_json_file is None:
            raise ValueError("ArmCortexM SDK requires an 'idau-json-file' argument to specify the IDAU layout. Please provide this with the '--idau-json-file' command line argument.")

        self.sau = SAU()
        self.idau = IDAU(idau_json_file)
        self.au = FullAttributionUnit(self.idau, self.sau)
        self.init_state.register_plugin("full_attribution_unit", self.au)

        # Setup ELF segments (skip first segment)
        for segment in list(elffile.iter_segments())[1:]:
            seg_addr = segment.header.p_paddr
            seg_data = segment.data()
            console.print(f"Loading segment at {hex(seg_addr)} with size {len(seg_data)}")
            init_state.memory.store(seg_addr, seg_data, with_enclave_boundaries=False)

    @staticmethod
    def detect(elffile, binpath):
        if elffile.get_machine_arch() != "ARM":
            return ""
        attributes = elffile.get_section_by_name(".ARM.attributes")
        if not attributes:
            logger.warning("No .ARM.attributes section found in ARM ELF file, guessing ARMv8-M")
            return "arm-v8-m"
        data = attributes.data()
        if data[17:25].decode("ascii") == "8-M.MAIN":
            return "arm-v8-m"
        return ""

    @staticmethod
    def get_sdk_name():
        return "arm-cortex-m"

    @staticmethod
    def get_angr_arch():
        return "ARMCortexM"

    def get_safe_registers(self) -> list[str]:
        # Banked and pseudo registers
        return super().get_safe_registers() + ["control", "cc_op", "itstate", "msp", "msp_s", "psp", "psp_s", "sp", "primask"]

    def init_eenter_state(self, eenter_state):
        pass

    def modify_init_state(self, init_state):
        # Setup initial PC
        set_reg_value(init_state, "pc", self.get_entry_addr())

        # set_reg_value(eenter_state, "control", 0b10)  # Use PSP and unprivileged mode

        # set_reg_value(eenter_state, "sp", 0x30012000)

        init_state.globals["secure"] = True
        init_state.globals["secure_init_finished"] = False

        self.setup_sau(init_state)
        self.setup_banked_register_hooks(init_state)

        # Load flash contents
        for addr, file in [(0x0C00E000, "flash.bin")]:
            try:
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                flash_path = os.path.join(base_dir, "assets", file)
                if os.path.exists(flash_path):
                    with open(flash_path, "rb") as f:
                        content = f.read()
                        init_state.memory.store(addr, content)
                        logger.info(f"Loaded {file} content to {hex(addr)} from {flash_path}")
                else:
                    logger.warning(f"{file} not found at {flash_path}")
            except Exception as e:
                logger.error(f"Failed to load {file}: {e}")

    def get_reentry_fanout(self, state):
        from explorer.hookers.arm_hooks import nsc_fan_out  # import here to avoid circular imports

        return nsc_fan_out(state)

    def get_max_inst_size(self):
        # Maximum instruction size for ARMv8-M is 4 bytes
        return 4

    def get_entry_addr(self):
        return self.project.entry

    def get_enclave_range(self):
        return self.au.get_enclave_ranges()

    def setup_sau(self, state):
        from explorer.hookers.arm_hooks import setup_sau_hook  # import here to avoid circular imports

        logger.info("Setting up SAU configuration hook...")
        state.inspect.b(
            "mem_write",
            when=angr.BP_AFTER,
            action=setup_sau_hook,
        )

        state.globals["sau_setup_done"] = False

    def setup_banked_register_hooks(self, state):
        def should_use_msp(state):
            # TODO: check if symbolic
            # Use MSP if
            # - Handler mode: IPSR != 0
            # - Thread mode and CONTROL[1] == 0
            return state.solver.eval(state.regs.cpsr & 0x1FF) != 0 or (state.solver.eval(state.regs.control & 0b10) == 0)

        def sp_write_hook(state):
            # TODO: also possible to use NS banked SPs?
            # Use MSP if
            # - Handler mode: IPSR != 0
            # - Thread mode and CONTROL[1] == 0
            if should_use_msp(state):
                set_reg_value(state, "msp", state.regs.sp)
            else:
                set_reg_value(state, "psp", state.regs.sp)

        def xsp_write_hook(state):
            # Update SP based on current mode
            if should_use_msp(state):
                set_reg_value(state, "sp", state.regs.msp)
            else:
                set_reg_value(state, "sp", state.regs.psp)

        state.inspect.b(
            "reg_write",
            reg_write_offset=self.project.arch.sp_offset,
            when=angr.BP_AFTER,
            action=sp_write_hook,
        )

        for reg_name in ["msp", "psp"]:
            reg_offset = self.project.arch.registers[reg_name][0]
            state.inspect.b(
                "reg_write",
                reg_write_offset=reg_offset,
                when=angr.BP_AFTER,
                action=xsp_write_hook,
            )

    def get_non_secure_callable_regions(self):
        return self.au.get_nsc_ranges()

    def is_thumb_mode(self):
        return True


def taint_mem_annotations() -> tuple[claripy.Annotation, ...]:
    # TODO: maybe also add MemoryAddressAnnotation
    return (AttackerTaintConservative(), UninitializedAnnotation())
