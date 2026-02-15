import logging

from angr import BP_AFTER, BP_BEFORE
from angr.storage.memory_mixins.memory_mixin import MemoryMixin

import pandora_options as po
from explorer.enclave import buffer_entirely_inside_enclave, buffer_touches_enclave

logger = logging.getLogger(__name__)


class EnclaveBreakpoingGeneratorMixin(MemoryMixin):
    """
    This class is responsible for generating breakpoints for memory accesses to enclave memory.
    It will not yet handle the memory accesses itself, but only generate the breakpoints.
    The actual handling of the memory accesses is done in the EnclaveAwareMixin, which is executed after this mixin and after the size is concretized.
    """

    def store(self, addr, data, size=None, **kwargs):
        with_enclave_boundaries = kwargs.pop("with_enclave_boundaries", True)
        breakpoint_event = ""

        if size is None:
            size = len(data) // self.state.arch.byte_width

        # Only enable the mixin if store is called with_enclave_boundaries (default on)
        mixin_enabled = self.category == "mem" and with_enclave_boundaries and po.PandoraOptions().get_option(po.PANDORA_ENCLAVE_MIXIN_ENABLE)

        if mixin_enabled:
            if buffer_entirely_inside_enclave(self.state, addr, size):
                """
                Case: Store on buffer that fully lies inside the enclave
                """
                breakpoint_event = "trusted_mem_write"

            elif buffer_touches_enclave(self.state, addr, size):
                """
                Case: Store on Buffer that can lie outside OR inside the enclave
                """
                # --> Trigger touches breakpoint
                breakpoint_event = "inside_or_outside_mem_write"

            else:
                """
                Case: Store on fully untrusted buffer
                """
                breakpoint_event = "untrusted_mem_write"

            self.state._inspect(
                breakpoint_event,
                BP_BEFORE,
                mem_write_address=addr,
                mem_write_length=size,
                mem_write_expr=data,
            )

            kwargs["breakpoint_event"] = breakpoint_event

        # All other stores are performed normally by passing them down
        r = super().store(addr, data, size=size, **kwargs)

        if mixin_enabled:
            # After the store, call the breakpoint again
            self.state._inspect(
                breakpoint_event,
                BP_AFTER,
                mem_write_address=addr,
                mem_write_length=size,
                mem_write_expr=data,
            )

        return r

    def load(self, addr, size=None, **kwargs):
        with_enclave_boundaries = kwargs.pop("with_enclave_boundaries", True)
        breakpoint_event = ""

        # Only enable the mixin if load is called with_enclave_boundaries (default on)
        # For enclave memory, we only care about memory loads
        mixin_enabled = with_enclave_boundaries and po.PandoraOptions().get_option(po.PANDORA_ENCLAVE_MIXIN_ENABLE) and self.category == "mem"

        if mixin_enabled:
            if buffer_entirely_inside_enclave(self.state, addr, size):
                logger.log(logging.TRACE, f"Reading enclave memory @{addr} size {size}")
                breakpoint_event = "trusted_mem_read"
            elif buffer_touches_enclave(self.state, addr, size):
                print(f"Reading memory that may lie inside or outside the enclave @{addr} size {size}")
                breakpoint_event = "inside_or_outside_mem_read"
            else:
                # Addr is NOT in enclave range
                breakpoint_event = "untrusted_mem_read"

            # Trigger read BEFORE breakpoint
            self.state._inspect(breakpoint_event, BP_BEFORE, mem_read_address=addr, mem_read_length=size)

            kwargs["breakpoint_event"] = breakpoint_event

        # Trusted reads proceed normally
        r = super().load(addr, size=size, **kwargs)

        if mixin_enabled:
            # Trigger post load trusted_mem_read
            self.state._inspect(
                breakpoint_event,
                BP_AFTER,
                mem_read_address=addr,
                mem_read_length=size,
                mem_read_expr=r,
            )

        return r
