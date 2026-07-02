import logging
import os
import re

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

        self.tfm_func_num = kwargs.get("tfm_func_num", -1)

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
        return super().get_safe_registers() + ["control", "cpsr", "cc_op", "cc_dep1", "itstate", "msp", "msp_s", "psp", "psp_s", "sp", "primask"]

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
        if self.project.loader.find_symbol("tfm_psa_call_veneer") and reentry_state.addr == self.project.loader.find_symbol("tfm_psa_call_veneer").rebased_addr:
            logger.info("Modifying reentry state for tfm_psa_call_veneer...")
            # Loop over all possible constraints and return all possible states
            next_states = []
            # next_states += self.setup_crypto_constraints(reentry_state.copy())
            # next_states += self.setup_its_constraints(reentry_state.copy())
            # next_states += self.setup_sp_platform_constraints(reentry_state.copy())
            # next_states += self.setup_attest_constraints(reentry_state.copy())
            next_states += self.setup_fwu_constraints(reentry_state.copy())
            if self.tfm_func_num != -1:
                logger.info(f"Calling function {next_states[self.tfm_func_num].globals.get('tfm_group', 'unknown')}::{next_states[self.tfm_func_num].globals.get('tfm_function', 'unknown')} based on tfm_func_num = {self.tfm_func_num}")
                return [next_states[self.tfm_func_num]]
            return next_states
        else:
            for symbol in ["tfm_psa_connect_veneer", "tfm_psa_close_veneer", "tfm_psa_version_veneer", "tfm_psa_framework_version_veneer"]:
                if self.project.loader.find_symbol(symbol) and reentry_state.addr == self.project.loader.find_symbol(symbol).rebased_addr:
                    reentry_state.globals["tfm_group"] = "other"
                    reentry_state.globals["tfm_function"] = symbol.replace("_veneer", "").replace("tfm_psa_", "")
            return [reentry_state]

    def setup_crypto_constraints(self, reentry_state):
        # Memory breakpoint when the address in r2 (in_vec) is accessed, to add constraints on the input buffer
        # To go to crypto partition
        def in_vec_mem_read_hook(state, group_id, func_num):
            if state.solver.is_true(state.inspect.mem_read_address == reentry_state.regs.r2):
                expr = state.inspect.mem_read_expr
                in_vec_base = claripy.BVS("in_vec_base", 32, annotations=taint_mem_annotations())
                new_expr = claripy.Concat(
                    in_vec_base.reversed,
                    claripy.BVV(0x38, 32).reversed,  # len(tfm_crypto_pack_iovec)
                )
                if expr.size() != new_expr.size():
                    new_expr = claripy.Concat(new_expr, claripy.Extract(expr.size() - new_expr.size() - 1, 0, expr))
                state.inspect.mem_read_expr = new_expr

                logger.info(f"Reading from in_vec address {state.inspect.mem_read_address}, r2 = {reentry_state.regs.r2}, reading expression: {state.inspect.mem_read_expr}")

            elif not isinstance(state.inspect.mem_read_address, int) and not state.inspect.mem_read_address.concrete and any(ast.symbolic and bool(re.match("^in_vec_base_[0-9]+_32$", ast.args[0])) for ast in state.inspect.mem_read_address.leaf_asts()):
                # Now, we can add the constraints
                # expr is of type `tfm_crypto_pack_iovec`
                #   - `psa_key_id_t key_id` (to specify key), which is located at offset 0.
                #   - `psa_algorithm_t alg` (to specify algorithm), which is located at offset 4.
                #   - `uint16_t function_id` (to specify specific function), which is located at offset 40.
                # Need to reverse required bytes due to endianness
                key_id = None
                alg = None

                function_id = None
                if group_id is not None and func_num is not None:
                    function_id = (group_id << 8) | func_num

                old_expr = state.inspect.mem_read_expr
                new_expr = claripy.BVV(0, 0)

                if key_id is not None:
                    new_expr = claripy.Concat(new_expr, claripy.BVV(key_id, 32).reversed)
                else:
                    new_expr = claripy.Concat(new_expr, claripy.BVS("key_id", 32, annotations=taint_mem_annotations()).reversed)

                if alg is not None:
                    new_expr = claripy.Concat(new_expr, claripy.BVV(alg, 32).reversed)
                else:
                    new_expr = claripy.Concat(new_expr, claripy.BVS("alg", 32, annotations=taint_mem_annotations()).reversed)

                new_expr = claripy.Concat(new_expr, claripy.BVS("padding1", 256, annotations=taint_mem_annotations()).reversed)

                if function_id is not None:
                    new_expr = claripy.Concat(new_expr, claripy.BVV(function_id, 32).reversed)
                else:
                    new_expr = claripy.Concat(new_expr, claripy.BVS("function_id", 32, annotations=taint_mem_annotations()).reversed)

                if old_expr.size() > new_expr.size():
                    new_expr = claripy.Concat(new_expr, claripy.Extract(old_expr.size() - new_expr.size() - 1, 0, old_expr))
                elif old_expr.size() < new_expr.size():
                    logger.critical(f"New expression size {new_expr.size()} is larger than old expression size {old_expr.size()}, cannot replace mem_read_expr")

                state.inspect.mem_read_expr = new_expr

        group_functions = {
            "random": (1, {"generate_random": 0}),
            "key_management": (2, {"get_key_attributes": 0, "open_key": 1, "close_key": 2, "import_key": 3, "destroy_key": 4, "export_key": 5, "export_public_key": 6, "purge_key": 7, "copy_key": 8, "generate_key": 9}),
            "hash": (3, {"compute": 0, "compare": 1, "setup": 2, "update": 3, "clone": 4, "finish": 5, "verify": 6, "abort": 7, "can_do_hash": 8}),
            "mac": (4, {"compute": 0, "verify": 1, "sign_setup": 2, "verify_setup": 3, "update": 4, "sign_finish": 5, "verify_finish": 6, "abort": 7}),
            "cipher": (5, {"encrypt": 0, "decrypt": 1, "encrypt_setup": 2, "decrypt_setup": 3, "generate_iv": 4, "set_iv": 5, "update": 6, "finish": 7, "abort": 8, "can_do_cipher": 9}),
            "aead": (6, {"encrypt": 0, "decrypt": 1, "encrypt_setup": 2, "decrypt_setup": 3, "generate_nonce": 4, "set_nonce": 5, "set_lengths": 6, "update_ad": 7, "update": 8, "finish": 9, "verify": 10, "abort": 11}),
            "asym_sign": (7, {"sign_message": 0, "verify_message": 1, "sign_hash": 2, "verify_hash": 3}),
            "asym_encrypt": (8, {"encrypt": 0, "decrypt": 1}),
            "key_derivation": (9, {"raw_key_agreement": 0, "setup": 1, "get_capacity": 2, "set_capacity": 3, "input_bytes": 4, "input_key": 5, "input_integer": 6, "key_agreement": 7, "output_bytes": 8, "output_key": 9, "abort": 10}),
        }

        states = []
        for group_name, (group_id, functions) in group_functions.items():
            for func_name, func_num in functions.items():
                new_state = reentry_state.copy()
                new_state.inspect.b(
                    "mem_read",
                    when=angr.BP_AFTER,
                    # We need to bind the current group_id and func_num to the hook function, otherwise they will be overwritten in the loop
                    # This will result in the last group_id and func_num being used for all hooks, which is not what we want
                    action=lambda s, bound_gid=group_id, bound_fid=func_num: in_vec_mem_read_hook(s, group_id=bound_gid, func_num=bound_fid),
                )
                new_state.globals["tfm_group"] = group_name
                new_state.globals["tfm_function"] = func_name
                new_state.globals["handle"] = 0x40000100
                states.append(new_state)
        return states

    def setup_its_constraints(self, reentry_state):
        return []

    def setup_sp_platform_constraints(self, reentry_state):
        return []

    def setup_attest_constraints(self, reentry_state):
        return []

    def setup_fwu_constraints(self, reentry_state: angr.SimState):
        reentry_state.globals["tfm_group"] = "fwu"
        reentry_state.globals["tfm_function"] = "run_fwu"

        # Setup fwu_ctx (2 x 8 bytes)
        reentry_state.memory.store(0x30023DA0, claripy.BVS("fwu_ctx", 2 * 8 * 8))

        # Setup mcuboot_ctx (2 x 8 bytes)
        # reentry_state.memory.store(0x30023DCC, claripy.BVS("mcuboot_ctx", 2 * 8 * 8))

        funcs = {
            "TFM_FWU_START": 1001,  # 0
            "TFM_FWU_WRITE": 1002,  # 1
            "TFM_FWU_FINISH": 1003,  # 2
            "TFM_FWU_CANCEL": 1004,  # 3
            "TFM_FWU_INSTALL": 1005,  # 4
            "TFM_FWU_CLEAN": 1006,  # 5
            "TFM_FWU_REJECT": 1007,  # 6
            "TFM_FWU_REQUEST_REBOOT": 1008,  # 7
            "TFM_FWU_ACCEPT": 1009,  # 8
            "TFM_FWU_QUERY": 1010,  # 9
        }
        states = []
        for func_name, func_num in funcs.items():
            state: angr.SimState = reentry_state.copy()
            state.globals["tfm_group"] = "fwu"
            state.globals["tfm_function"] = func_name.replace("TFM_FWU_", "").lower()
            state.globals["handle"] = 0x40000104
            state.globals["type_arg"] = func_num

            if func_name != "TFM_FWU_START":
                # First call `fwu_bootloader_staging_area_init(component, *manifest, manifest_size)`
                addr = state.project.loader.find_symbol("fwu_bootloader_staging_area_init")
                if addr is not None:
                    return_addr = state.addr
                    state.regs.r0 = 0
                    state.regs.r1 = claripy.BVS("manifest_ptr", 32, annotations=taint_mem_annotations())
                    state.regs.r2 = 0
                    state.regs.lr = return_addr
                    state.regs.ip = addr.rebased_addr

            states.append(state)
        return states

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
