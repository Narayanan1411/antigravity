# features.py
from state import state
import numpy as np

def compute_and_reset():
    def avg(x): return float(np.mean(x)) if x else 0
    def spike(x): return float(max(x) - min(x)) if len(x) > 1 else 0

    # ---- CPU ----
    cpu_avg = avg(state.cpu_samples)
    cpu_spike = spike(state.cpu_samples)

    # ---- Memory ----
    memory_percent = avg(state.mem_samples)
    memory_spike = spike(state.mem_samples)

    # ---- Load ----
    load_avg_delta = spike(state.load_samples)

    # ---- Disk IO ----
    if len(state.disk_io_samples) > 1:
        disk_io_rate = (state.disk_io_samples[-1] - state.disk_io_samples[0]) / len(state.disk_io_samples)
    else:
        disk_io_rate = 0

    disk_io_spike = spike(state.disk_io_samples)

    # ---- Process ----
    process_count = avg(state.process_count_samples)
    new_process_rate = spike(state.process_count_samples)

    # ---- Network ----
    if len(state.net_samples) > 1:
        bytes_out = state.net_samples[-1][0] - state.net_samples[0][0]
        bytes_in = state.net_samples[-1][1] - state.net_samples[0][1]
    else:
        bytes_out = bytes_in = 0

    # ---- Reset ----
    state.cpu_samples.clear()
    state.mem_samples.clear()
    state.disk_io_samples.clear()
    state.load_samples.clear()
    state.process_count_samples.clear()
    state.net_samples.clear()

    return {
        "cpu_avg": cpu_avg,
        "cpu_spike": cpu_spike,
        "memory_percent": memory_percent,
        "memory_spike": memory_spike,
        "load_avg_delta": load_avg_delta,
        "disk_io_rate": disk_io_rate,
        "disk_io_spike": disk_io_spike,

        "process_count": process_count,
        "new_process_rate": new_process_rate,

        "bytes_out_server": bytes_out,
        "bytes_in_server": bytes_in
    }