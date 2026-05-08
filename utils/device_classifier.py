def classify_device(os_name: str, mac_vendor: str = None) -> str:
    """Classify the device based on OS string or MAC vendor fallback."""
    # 1. Try OS-based classification first
    if os_name:
        os_lower = os_name.lower()
        if "windows" in os_lower or "mac" in os_lower or "ubuntu" in os_lower or "linux" in os_lower:
            return "laptop"
        if "android" in os_lower or "ios" in os_lower:
            return "mobile"
        if "tizen" in os_lower or "smarttv" in os_lower:
            return "iot"

    # 2. Fallback to MAC vendor classification
    if mac_vendor:
        v_lower = mac_vendor.lower()
        if "apple" in v_lower or "dell" in v_lower or "lenovo" in v_lower:
            return "workstation"      # Apple could be phone, but usually workstation on corporate nets
        if "samsung" in v_lower or "xiaomi" in v_lower or "google" in v_lower:
            return "mobile"
        if "tp-link" in v_lower or "netgear" in v_lower or "belkin" in v_lower or "ring" in v_lower:
            return "iot"
        if "vmware" in v_lower or "virtualbox" in v_lower or "docker" in v_lower:
            return "server"

    return "unknown"
