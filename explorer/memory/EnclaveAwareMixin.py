import logging

from angr.storage.memory_mixins.memory_mixin import MemoryMixin

from explorer.taint import get_tainted_mem_bits

logger = logging.getLogger(__name__)


class EnclaveAwareMixin(MemoryMixin):
    """
    This mixin is responsible for handling memory accesses to enclave memory.
    It is executed after the EnclaveBreakpointGeneratorMixin, which generates the breakpoints for enclave memory accesses, and after the size is concretized.
    """

    def store(self, addr, data, size=None, **kwargs):
        breakpoint_event = kwargs.pop("breakpoint_event", "")

        if breakpoint_event == "untrusted_mem_write" or breakpoint_event == "inside_or_outside_mem_write":
            """
                Addresses that are not FULLY in enclave range: Ignore the store
                This is the conservative approach to simulating enclave memory:
                 - Buffers fully inside the enclave are simulated normally
                 - ALL other buffers are completely symbolized and ignored
                 Note, that the breakpoint has already triggered, so we still allow all reports of the security
                  implications of such stores. But for Pandora, we now functionality-wise symbolize this store
                  by ignoring it.
                This also impacts partial buffers that may lie outside OR inside. These are also ignored for stores and
                  the ptrsan plugin needs to make sure we report it properly as a security issue.
                """
            logger.debug(f"Ignoring untrusted {self.category} store @ {addr}.")

            return None

        # All other stores are performed normally by passing them down
        r = super().store(addr, data, size=size, **kwargs)

        return r

    def load(self, addr, size=None, **kwargs):
        breakpoint_event = kwargs.pop("breakpoint_event", "")

        if breakpoint_event == "inside_or_outside_mem_read" or breakpoint_event == "untrusted_mem_read":
            """
                Note: this else case is triggered:
                1. when the load touches partly the enclave (i.e. half of the load is outside and half is inside), or
                2. when the load fully lies outside the enclave
                Both cases will be handled by returning a fully symbolic attacker tainted data.
                This is the conservative handling of partially untrusted loads.
                However, we first triggered the respective breakpoint, create the load, and then trigger the post
                breakpoint before returning.
            """
            mem = get_tainted_mem_bits(self.state, size * 8)
            logger.debug(f"Simulating untrusted {self.category} load @ {addr} with a tainted BVS {mem}.")

            # Early return the untrusted read
            return mem

        # Trusted reads proceed normally
        r = super().load(addr, size=size, **kwargs)

        return r
