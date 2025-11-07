import logging

from angr import SimProcedure
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

import ui.log_format
from explorer.hookers.abstract_hooker import AbstractHooker
from explorer.hookers.general_hooks import SimNop
from explorer.hookers.x86_hooks import Rdrand, SimAbort, SimEnclu, SimFxrstor, SimFxsave, SimLdmxcsr, SimMemcmp, SimMemcpy, SimMemset, SimRep, SimRet, SimVzeroall
from sdks.SymbolManager import SymbolManager

logger = logging.getLogger(__name__)


class SGXHooker(AbstractHooker):
    """
    This class manages the hooking of instructions. It is loosely based on Guardian's class of the same name.
    """

    fct_map = {
        "memcpy": SimMemcpy,
        "memset": SimMemset,
        "memcmp": SimMemcmp,
        # TODO hack to skip the time ocall in Zircon pal_linux_main
        "_DkSystemTimeQuery": SimRet,
        # TODO hack to skip zircon mbedtls init (angr errors with something like unsupported dirty helper amd64 aeskeygen)
        "PalCryptoInit": SimRet,
        # TODO hack to skip unsupported aes instructions in DCAP PLE
        "aesni_setkey_enc_128": SimRet,
        "mbedtls_aesni_crypt_ecb": SimRet,
    }
    fct_addr_map = {}

    def __init__(self, init_state):
        super().__init__(init_state)
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.skipdata = True

        for f, proc in self.fct_map.items():
            addr = self.hook_fct_addr(f)
            if addr:
                self.fct_addr_map[addr] = (f, proc())

    def hook_fct_addr(self, name):
        addr = SymbolManager().symbol_to_addr(name)
        if addr is not None:
            logger.debug(ui.log_format.format_fields(f"hooking function <{name}> at {addr:#x}"))
            logger.debug(ui.log_format.format_asm(self.init_state, use_ip=addr))
        return addr

    def hook_mem_region(self, addr, size):
        """
        Hooks a whole memory region at once with SimProcedures.
        :param addr: Address to start hooking at
        :param size: Size of the region
        """

        section_bytes = self.project.loader.memory.load(addr, size)

        for i in self.md.disasm(section_bytes, addr):
            sim_proc = self.instruction_replacement(i)
            fct = ""
            if i.address in self.fct_addr_map.keys():
                fct, sim_proc = self.fct_addr_map[i.address]
            if sim_proc is not None:
                tab_str = f"{i.address:#x}:\t{i.mnemonic:<10}\t{i.op_str:<20}\t{i.size:<3}\t{fct}"
                if fct != "" and sim_proc.NEEDS_ENDBR and "endbr" not in i.mnemonic:
                    logger.warning(tab_str + " SKIPPING (no endbr)")
                    continue

                if type(sim_proc) is not SimAbort:
                    logger.debug(tab_str)

                self.project.hook(i.address, hook=sim_proc, length=i.size)

    # Prepare a dict with instruction replacements and their replacement class
    instruction_hooks = {
        "enclu": SimEnclu,
        "xsavec64": SimFxsave,
        "xsave64": SimFxsave,
        "fxsave64": SimFxsave,
        "ldmxcsr": SimLdmxcsr,
        "fxrstor": SimFxrstor,
        "fxrstor64": SimFxrstor,
        "xrstor": SimFxrstor,
        "xrstor64": SimFxrstor,
        "vzeroall": SimVzeroall,
        "rdrand": Rdrand,
        "int3": SimAbort,
        "verw": SimNop,
        # rep is handled by SimRep but is  checked for partial and not complete equality below.
    }

    def instruction_replacement(self, capstone_instruction) -> SimProcedure | None:
        """
        Replaces a capstone instruction with a SimProcedure or returns None if no replacement is necessary.
        :param capstone_instruction: Instruction as returned by the disassembler
        :return: A SimProcedure or None
        """
        size = capstone_instruction.size

        mnemonic = capstone_instruction.mnemonic
        # General case: If we have a hook for it, use that.
        if mnemonic in self.instruction_hooks:
            return self.instruction_hooks[mnemonic](opstr=capstone_instruction.op_str, bytes_to_skip=size, mnemonic=mnemonic)
        # Edge case, rep may look differently each time but always starts with rep
        elif capstone_instruction.mnemonic[0:4] == "rep ":
            return SimRep(inst=capstone_instruction)
        # Default case: No replacement
        else:
            return None
