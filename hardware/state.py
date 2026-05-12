# state.py
from collections import deque
import time

class MetricsState:
    def __init__(self):
        self.start_time = time.time()
        self.cpu_samples = []
        self.mem_samples = []
        self.disk_io_samples = []
        self.load_samples = []

        self.process_count_samples = []
        self.net_samples = []

        self.last_reset = time.time()

state = MetricsState()