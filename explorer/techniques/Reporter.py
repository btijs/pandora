import csv
import itertools
import logging
import time
from pathlib import Path

import psutil
from angr import ExplorationTechnique

from ui import console
from ui.report import generate_basedir

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

    def setup(self, simgr):
        self.start_time = time.perf_counter()
        if simgr.active:
            binpath = Path(simgr.active[0].project.filename)
        basedir = generate_basedir("report_folder", binpath)
        self.filename = basedir / f"num_states_stats_{binpath.stem}.csv"
        with open(self.filename, "w") as f:
            f.write("step_nr,timestamp,memory_usage,nr_of_states,addr\n")
        console.print(f"Reporter: logging to {self.filename}")

    def step(self, simgr, **kwargs):
        """
        Performs some logging: step_nr, timestamp, memory usage, nr of states
        """
        step_nr = self.step_nr
        self.step_nr += 1
        timestamp = time.perf_counter() - self.start_time
        process = psutil.Process()
        memory_usage = process.memory_info().rss
        nr_of_states = len(set(itertools.chain.from_iterable(val for key, val in simgr.stashes.items() if key not in ["unsat", "uniques", "incorrect", "unconstrained", "deadended", "errored", "unsat"])))

        self.stats.append(
            (
                step_nr,
                timestamp,
                memory_usage,
                nr_of_states,
                [hex(s.addr) for s in simgr.active[:10]] + (["..."] if len(simgr.active) > 10 else []),
            )
        )

        # write to file every 100 steps
        if step_nr % 100 == 0 and self.stats:
            self.write()
            self.stats = []

        return simgr.step(**kwargs)

    def finish(self):
        if self.stats:
            self.write()
            self.stats = []

    def write(self):
        with open(self.filename, "a") as f:
            writer = csv.writer(f)
            for step_nr, timestamp, memory_usage, nr_of_states, addr in self.stats:
                writer.writerow([step_nr, timestamp, memory_usage, nr_of_states, addr])
