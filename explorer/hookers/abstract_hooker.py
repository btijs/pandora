class AbstractHooker:
    def __init__(self, init_state):
        self.init_state = init_state
        self.project = init_state.project

    def hook_mem_region(self, addr, size):
        raise NotImplementedError
