import logging

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_V8, Cs

from explorer.hookers.abstract_hooker import AbstractHooker
from explorer.hookers.arm_hooks import SimBXNS, SimSG, SimTestTarget
from explorer.hookers.general_hooks import SimNop

logger = logging.getLogger(__name__)


class Armv8MHooker(AbstractHooker):
    def hook_mem_region(self, addr, size):
        if "full_attribution_unit" not in self.init_state.globals:
            raise ValueError("Full Attribution Unit not found in init_state.globals")
        au = self.init_state.globals["full_attribution_unit"]

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

                hook = SimTestTarget(rd=rd, rn=rn, attribution_unit=au, a_flag=a_flag, t_flag=t_flag)
                self.project.hook(instr.address, hook, length=instr.size)
            elif instr.mnemonic == "sg":
                logger.info(f"Found SG instruction at address 0x{instr.address:x}. Hooking now...")
                sg_instr_addrs.append(instr.address)

                hook = SimSG()
                self.project.hook(instr.address, hook, length=instr.size)
            elif instr.mnemonic == "bkpt":
                logger.info(f"Found BKPT instruction at address 0x{instr.address:x} {instr.size}. Hooking now...")

                hook = SimNop(bytes_to_skip=instr.size, mnemonic=instr.mnemonic, opstr=instr.op_str)
                self.project.hook(instr.address, hook, length=instr.size)
            elif instr.mnemonic == "blxns" or instr.mnemonic == "bxns":
                logger.info(f"Found {instr.mnemonic.upper()} instruction at address 0x{instr.address:x}. Hooking now...")
                hook = SimBXNS(sg_instr_addrs=sg_instr_addrs)
                self.project.hook(instr.address, hook, length=instr.size)

        self.init_state.globals["sg_instr_addrs"] = sg_instr_addrs
