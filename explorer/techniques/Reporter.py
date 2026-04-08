import itertools
import logging
import time
from pathlib import Path

import psutil
from angr import ExplorationTechnique

logger = logging.getLogger(__name__)


class Reporter(ExplorationTechnique):
    """
    Exploration technique to trace log states.
    """

    def __init__(self):
        super().__init__()
        # list of tuple(step_nr, timestamp, memory_usage, nr_of_states)
        self.stats = []
        self.step_nr = 0
        self.start_time = time.perf_counter()
        self.project_name = None

    def step(self, simgr, **kwargs):
        """
        Performs some logging: step_nr, timestamp, memory usage, nr of states
        """
        if self.project_name is None:
            if simgr.active:
                self.project_name = Path(simgr.active[0].project.filename).stem
        step_nr = self.step_nr
        self.step_nr += 1
        timestamp = time.perf_counter() - self.start_time
        process = psutil.Process()
        memory_usage = process.memory_info().rss
        nr_of_states = len(set(itertools.chain.from_iterable(val for key, val in simgr.stashes.items() if key not in ["unsat", "uniques", "incorrect", "unconstrained", "deadended", "errored", "unsat"])))

        self.stats.append((step_nr, timestamp, memory_usage, nr_of_states))

        return simgr.step(**kwargs)

    def finish(self):
        with open(f"num_states_stats_{self.project_name}.csv", "w") as f:
            f.write("step_nr,timestamp,memory_usage,nr_of_states\n")
            for step_nr, timestamp, memory_usage, nr_of_states in self.stats:
                f.write(f"{step_nr},{timestamp:.8f},{memory_usage},{nr_of_states}\n")
