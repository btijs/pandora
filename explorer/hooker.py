from __future__ import annotations

import logging

import ui.log_format
from explorer.hookers.sancus_hooker import SancusHooker
from explorer.hookers.x86_hooker import SGXHooker

logger = logging.getLogger(__name__)


# XXX this could also be passed via the SDKManager if we get >1 TEE-specific hooker per architecture
HOOKERS = {"x86_64": SGXHooker, "msp430": SancusHooker}


class HookerManager:
    def __init__(self, init_state, exec_ranges=None, live_console=None, task=None, angr_arch="x86_64"):
        self.init_state = init_state
        self.project = init_state.project
        self.exec_ranges = exec_ranges
        self.hooker = HOOKERS[angr_arch](init_state)

        logger.info("Hooking instructions.")
        loop_count = 0
        # Distinguish between ELF and memory dump: sections may be empty
        section_count = len(self.project.loader.main_object.sections)
        logger.debug("Address        \tInstruction\tOpstr               \tSize [Replacement function]")
        if section_count != 0:
            # Normal elf file, pick executable sections and start hooking
            if live_console:
                live_console.update(task, total=section_count, completed=0)
            for section in self.project.loader.main_object.sections:
                # note: skip NOBITS sections that are uninitialized
                if section.is_executable and not section.only_contains_uninitialized_data:
                    self.hooker.hook_mem_region(section.vaddr, section.memsize)
                loop_count += 1
                live_console.update(task, completed=loop_count)
        else:
            # Not a normal elf file. In this case, utilize the code pages we got
            if not exec_ranges:
                logger.error(ui.log_format.format_error("Can't hook without a memory layout yet!"))
                exit(1)

            total_count = len(self.exec_ranges)
            if live_console:
                live_console.update(task, total=total_count, completed=0)
            for offset, count in self.exec_ranges:
                self.hooker.hook_mem_region(offset, count)
                loop_count += 1
                live_console.update(task, completed=loop_count)
        logger.info("Hooking instructions completed.")
