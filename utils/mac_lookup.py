from __future__ import annotations

# In-memory MAC vendor OUI map (simplified)
vendors = {
    "00:1A:79": "Apple",
    "3C:5A:B4": "Apple",
    "90:32:4B": "Apple",
    "E2:45:45": "Apple",
    "50:0F:F5": "Apple",
    "7E:DA:21": "Apple",
    "62:89:48": "Apple",
    "98:4F:EE": "Samsung",
    "F4:F5:E8": "Xiaomi",
    "C0:25:E9": "TP-Link",
    "68:FF:7B": "TP-Link",
    "F4:5C:89": "Dell",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "08:00:27": "VirtualBox",
    "02:42:AC": "Docker",
}

def mac_vendor(mac: str) -> str | None:
    """Lookup MAC vendor from OUI."""
    if not mac or len(mac) < 8:
        return None

    prefix = mac.upper()[0:8]
    return vendors.get(prefix)
