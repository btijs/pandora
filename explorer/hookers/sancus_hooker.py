import logging
import re

from explorer.hookers.abstract_hooker import AbstractHooker
from explorer.hookers.general_hooks import SimNop
from explorer.hookers.sancus_hooks import SimAttest, SimClix, SimDecrypt, SimEncrypt, SimGetCallerID, SimGetID, SimProtect, SimUnprotect
from sdks.SymbolManager import SymbolManager

logger = logging.getLogger(__name__)


class SancusHooker(AbstractHooker):
    instruction_hooks = {
        "0x1380": SimUnprotect,
        "0x1381": SimProtect,
        "0x1382": SimAttest,
        "0x1384": SimEncrypt,
        "0x1385": SimDecrypt,
        "0x1386": SimGetID,
        "0x1387": SimGetCallerID,
        "0x1388": SimNop,
        "0x1389": SimClix,
    }

    def hook_mem_region(self, addr, size):
        SANCUS_INSTR_SIZE = 2
        entry_sym = SymbolManager().get_symbol_exact(addr)
        if entry_sym and re.search(r"__sm_(\w+)_entry|__sm_(\w+)_public_start", entry_sym):
            logger.debug(f"Hooking enclave section [{addr:#x},{addr + size:#x}] ({entry_sym})")
            disasm = SymbolManager().get_objdump(addr, addr + size, arch="msp430")

            for addr, opcode in self.get_sancus_instr_addresses(disasm.splitlines()):
                if opcode in self.instruction_hooks.keys():
                    sim_proc = self.instruction_hooks[opcode](opstr="", bytes_to_skip=2, mnemonic=opcode)
                    tab_str = f"{addr}:\t{opcode:<10}\t{sim_proc.__class__.__name__:<20}\t{str(SANCUS_INSTR_SIZE):<3}"
                    logger.debug(tab_str)
                    self.project.hook(int(addr, 16), hook=sim_proc, length=SANCUS_INSTR_SIZE)
                else:
                    logger.warning(f'Not hooking unrecognized instruction ".word {opcode}" @{addr}')
        else:
            logger.debug(f"Skipping non-enclave section [{addr:#x},{addr + size:#x}] ({entry_sym})")

    """
    Return a list with (address-opcode) pairs of all Sancus related instructions
    @param section: [String]
        a list of strings containing the objdump of the project
    @return [(address, opcode)]
        a list with address opcode pairs
    """

    def get_sancus_instr_addresses(self, section):
        instructions = []
        # Regex for following kind of line:
        #    6ca4:       86 13           .word   0x1386
        # where the address and the opcode (0x1386) get captured
        regex = re.compile(r"^\s{4}([0-9A-Fa-f]+).*\.word\s*(0x[0-9A-Fa-f]+)")
        for instr in section:
            if ".word" in instr:
                match = regex.match(instr)
                addr = match.group(1)
                op = match.group(2)
                instructions.append(("0x" + str(addr), op))
        return instructions
