import logging

from angr import SIM_PROCEDURES
from capstone import CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_V8, Cs

from explorer.hookers.abstract_hooker import AbstractHooker
from explorer.hookers.arm_hooks import SimBKPT, SimBXNS, SimSG, SimSkipFunction, SimSVC, SimTestTarget

logger = logging.getLogger(__name__)


class Armv8MHooker(AbstractHooker):
    def hook_mem_region(self, addr, size):
        sg_instr_addrs = self.init_state.globals.get("sg_instr_addrs", [])

        section_bytes = self.project.loader.memory.load(addr, size)
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_V8)
        md.detail = True
        md.skipdata = True
        for instr in md.disasm(section_bytes, addr):
            if instr.mnemonic in ["tt", "ttt", "tta", "ttat"]:
                # Different kind of TT instructions:
                # get security state and access permissions for access with <security lvl> + <privilege lvl>
                #   TT   -> current security level + current privilege level
                #   TTT  -> current security level + unprivileged
                #   TTA  -> non-secure + current privilege level (only available in secure state)
                #   TTAT -> non-secure + unprivileged (only available in secure state)
                rd = instr.reg_name(instr.operands[0].value.reg)
                rn = instr.reg_name(instr.operands[1].value.reg)
                logger.info(
                    f"Found {instr.mnemonic.upper()} instruction, rd = {rd}, rn = {rn} at address 0x{instr.address:x}. Hooking now...",
                )

                a_flag = instr.mnemonic in ["tta", "ttat"]
                t_flag = instr.mnemonic in ["ttt", "ttat"]

                hook = SimTestTarget(rd=rd, rn=rn, a_flag=a_flag, t_flag=t_flag)
                self.project.hook(instr.address, hook, length=instr.size)
            elif instr.mnemonic == "sg":
                logger.info(f"Found SG instruction at address 0x{instr.address:x}. Hooking now...")
                sg_instr_addrs.append(instr.address)

                hook = SimSG()
                self.project.hook(instr.address, hook, length=instr.size)
            elif instr.mnemonic == "bkpt":
                logger.info(f"Found BKPT instruction at address 0x{instr.address:x} {instr.size}. Hooking now...")
                hook = SimBKPT()
                # hook = SimNop(bytes_to_skip=instr.size, mnemonic=instr.mnemonic, opstr=instr.op_str)
                self.project.hook(instr.address, hook, length=instr.size)
            elif instr.mnemonic in ["blxns", "bxns"]:
                logger.info(f"Found {instr.mnemonic.upper()} instruction at address 0x{instr.address:x}. Hooking now...")
                reg = instr.reg_name(instr.operands[0].value.reg)
                hook = SimBXNS(jmp_reg=reg, l_flag=(instr.mnemonic.lower() == "blxns"))
                self.project.hook(instr.address, hook, length=instr.size)
            # elif instr.mnemonic in ["bx", "blx"]:
            #     logger.info(f"Found {instr.mnemonic.upper()} instruction at address 0x{instr.address:x}. Hooking now...")
            #     ret = instr.reg_name(instr.operands[0].value.reg)
            #     hook = SimBX(ret=ret, l_flag=(instr.mnemonic.lower() == "blx"))
            #     self.project.hook(instr.address, hook, length=instr.size)

            elif instr.mnemonic == "svc":
                logger.info(f"Found SVC instruction at address 0x{instr.address:x}. Hooking now...")
                hook = SimSVC(bytes_to_skip=instr.size, opstr=instr.op_str, svc_num=instr.operands[0].value.imm)
                self.project.hook(instr.address, hook, length=instr.size)

        self.init_state.globals["sg_instr_addrs"] = sg_instr_addrs

    def hook_symbols(self):
        self.project.hook_symbol("memset", SIM_PROCEDURES["libc"]["memset"]())
        self.project.hook_symbol("memcpy", SIM_PROCEDURES["libc"]["memcpy"]())
        self.project.hook_symbol("tfm_hal_system_reset", SimBKPT())

        for fun in [
            # "tfm_plat_otp_init",
            # "tfm_plat_provisioning_is_required",
            # "tfm_plat_provisioning_perform",
            # "tfm_plat_provisioning_check_for_dummy_keys",
            # "tfm_arch_set_secure_exception_priorities",
        ]:
            self.project.hook_symbol(fun, SimSkipFunction(function=fun))

        self.project.analyses.CFGFast()
        for addr, func in self.project.kb.functions.items():
            if "WaitOnFlag" in func.name or "WaitFor" in func.name:
                logger.info(f"Hooking {func} at address 0x{addr:x}...")
                self.project.hook_symbol(addr, SimSkipFunction(function=func))
