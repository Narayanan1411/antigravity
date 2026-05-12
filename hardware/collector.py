# collector.py
import psutil
import time
from state import state

def collect():
    while True:
        state.cpu_samples.append(psutil.cpu_percent(interval=None))
        state.mem_samples.append(psutil.virtual_memory().percent)
        state.load_samples.append(psutil.getloadavg()[0])

        disk = psutil.disk_io_counters()
        state.disk_io_samples.append(disk.read_bytes + disk.write_bytes)

        state.process_count_samples.append(len(psutil.pids()))

        net = psutil.net_io_counters()
        state.net_samples.append((net.bytes_sent, net.bytes_recv))

        time.sleep(1)  # ✅ low overhead