import logging
import os

import angr
import claripy
import z3

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

        # Setup ELF segments (skip first segment)
        for segment in list(elffile.iter_segments())[1:]:
            seg_addr = segment.header.p_paddr
            seg_data = segment.data()
            print(f"Loading segment at {hex(seg_addr)} with size {len(seg_data)}")
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
        return super().get_safe_registers() + ["control", "cpsr", "cc_op", "cc_dep1", "itstate", "msp", "msp_s", "psp", "psp_s"]

    def init_eenter_state(self, eenter_state):
        # Setup initial PC
        set_reg_value(eenter_state, "pc", self.get_entry_addr())

        # set_reg_value(eenter_state, "control", 0b10)  # Use PSP and unprivileged mode

        eenter_state.globals["secure"] = True

        self.setup_sau(eenter_state)
        self.setup_banked_register_hooks(eenter_state)

        # Load flash contents
        for addr, file in [(0x0C00E000, "flash.bin")]:
            try:
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                flash_path = os.path.join(base_dir, "assets", file)
                if os.path.exists(flash_path):
                    with open(flash_path, "rb") as f:
                        content = f.read()
                        eenter_state.memory.store(addr, content)
                        logger.info(f"Loaded {file} content to {hex(addr)} from {flash_path}")
                else:
                    logger.warning(f"{file} not found at {flash_path}")
            except Exception as e:
                logger.error(f"Failed to load {file}: {e}")

    def modify_init_state(self, init_state):
        pass

    def modify_reentry_state(self, reentry_state):
        logger.info(f"Modifying reentry state for ArmCortexM SDK... at address {hex(reentry_state.addr)}")
        if reentry_state.addr == self.project.loader.find_symbol("tfm_psa_call_veneer").rebased_addr:
            logger.info("Modifying reentry state for tfm_psa_call_veneer...")
            # Set constraints to select correct partition on reentry
            # First argument (r0) is handle
            # crypto: 0x40000100U
            # initial attestation: 0x40000103U
            # internal trusted storage: 0x40000102U
            # TODO: now hardcoded to crypto partition, make more generic
            handle = 0x40000100
            reentry_state.regs.r0 = handle

            mem_slice = None

            # Memory breakpoint when the address in r2 (in_vec) is accessed, to add constraints on the input buffer
            # To go to crypto partition
            def in_vec_mem_read_hook(state0):
                if not state0.solver.is_true(state0.inspect.mem_read_address == reentry_state.regs.r2):
                    return  # Not the in_vec address, ignore

                logger.info(f"Reading from in_vec address {state0.inspect.mem_read_address}, r2 = {reentry_state.regs.r2}")

                nonlocal mem_slice
                mem_slice = state0.inspect.mem_read_expr[255:224]

                # Memory breakpoint when the base address of the previous result is accessed
                # To go to specific crypto function within crypto partition
                def in_vec0_base_mem_read_hook(state1):
                    if isinstance(state1.inspect.mem_read_address, int) or state1.inspect.mem_read_address.concrete:
                        # Fast fail path
                        return

                    # Initialize the native Z3 Solver
                    s = z3.Solver()
                    bz3 = claripy.backends.z3

                    # Migrate existing constraints from Claripy to Z3
                    s.add(bz3.convert_list(state1.solver.constraints))

                    # Create fresh leaf variable
                    z3_proxy_mem = z3.BitVec("proxy_mem_32", 32)

                    # Convert your vectors and the "universal" variable
                    z3_original_slice = bz3.convert(mem_slice)
                    z3_vector_a = bz3.convert(state1.solver.simplify(state1.inspect.mem_read_address.reversed))
                    z3_vector_b = bz3.convert(mem_slice)

                    z3_vector_a_sub = z3.substitute(z3_vector_a, (z3_original_slice, z3_proxy_mem))
                    z3_vector_b_sub = z3.substitute(z3_vector_b, (z3_original_slice, z3_proxy_mem))

                    print("Z3 Mem Slice:", z3_original_slice)
                    print("Z3 Vector A:", z3_vector_a)
                    print("Z3 Vector B:", z3_vector_b)

                    s.add(z3_proxy_mem == z3_original_slice)

                    # Add the "Special Equality" condition
                    # Logic: "The path constraints must hold AND (For All mem, A == B)"
                    special_equality = z3.ForAll([z3_proxy_mem], z3_vector_a_sub == z3_vector_b_sub)
                    s.add(special_equality)

                    # 5. Solve
                    if s.check() != z3.sat:
                        return

                    print("SAT!")

                    # Now, we can add the constraints
                    # expr is of type `tfm_crypto_pack_iovec`, we are interested in `uint16_t function_id`, which is located at offset 40.
                    # Need to reverse 256 bytes due to endianness
                    state1.solver.add(state1.inspect.mem_read_expr[127:96] == claripy.BVV(256, 32).reversed)

                state0.inspect.b(
                    "mem_read",
                    when=angr.BP_AFTER,
                    action=in_vec0_base_mem_read_hook,
                )

            reentry_state.inspect.b(
                "mem_read",
                when=angr.BP_AFTER,
                action=in_vec_mem_read_hook,
            )

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
