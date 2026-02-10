class AbstractHooker:
    def __init__(self, init_state):
        self.init_state = init_state
        self.project = init_state.project

    def hook_mem_region(self, addr, size):
        raise NotImplementedError

    def hook_symbols(self):
        """
        This function can be implemented by subclasses to hook specific symbols in the binary.
        E.g. memset
        """
        pass
