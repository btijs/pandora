import logging

import angr

from sdks.AbstractSDK import AbstractSDK
from sdks.SAU_IDAU import IDAU, SAU, FullAttributionUnit
from utilities.angr_helper import set_reg_value

logger = logging.getLogger(__name__)


class ArmCortexM(AbstractSDK):
    def __init__(self, elffile, init_state, version_str, idau_json_file=None, **kwargs):
        super().__init__(elffile, init_state, version_str, **kwargs)

        print(f"Elf file: {elffile}")
        print(f"Init state: {init_state}")
        print(f"Version string: {version_str}")
        print(f"IDAU JSON file: {idau_json_file}")
        print(f"Additional kwargs: {kwargs}")

        if idau_json_file is None:
            raise ValueError("ArmCortexM SDK requires an 'idau-json-file' argument to specify the IDAU layout. Please provide this with the '--idau-json-file' command line argument.")

        self.sau = SAU()
        self.idau = IDAU(idau_json_file)
        self.au = FullAttributionUnit(self.idau, self.sau)
        self.init_state.register_plugin("full_attribution_unit", self.au)

    @staticmethod
    def detect(elffile, binpath):
        if elffile.get_machine_arch() != "ARM":
            return ""
        attributes = elffile.get_section_by_name(".ARM.attributes")
        if not attributes:
            logger.warning("No .ARM.attributes section found in ARM ELF file.")
            return ""
        data = attributes.data()
        if data[17:25].decode("ascii") == "8-M.MAIN":
            return "arm-v8-m"
        return ""

    @staticmethod
    def get_sdk_name():
        return "arm-cortex-m"

    @staticmethod
    def get_angr_arch():
        return "arm-v8-m"

    def init_eenter_state(self, eenter_state):
        # Setup initial PC
        set_reg_value(eenter_state, "pc", self.get_entry_addr())

        # TODO: find out more about these registers
        eenter_state.regs.cc_op = 0  # OP_COPY
        eenter_state.regs.cc_dep1 = 0

        eenter_state.regs.itstate = 0

        eenter_state.globals["secure"] = True

        self.setup_sau(eenter_state)

    def modify_init_state(self, init_state):
        pass

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

    def get_non_secure_callable_regions(self):
        return self.au.get_nsc_ranges()
