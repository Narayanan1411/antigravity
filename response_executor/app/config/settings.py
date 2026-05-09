from dotenv import load_dotenv
import os

load_dotenv()

class Settings:

    # Router
    ROUTER_HOST = os.getenv("ROUTER_HOST")
    ROUTER_USER = os.getenv("ROUTER_USER")
    ROUTER_PASSWORD = os.getenv("ROUTER_PASSWORD")
    HOTSPOT_INTERFACE = os.getenv("HOTSPOT_INTERFACE")

    # Compute Machine
    COMPUTE_HOST = os.getenv("COMPUTE_HOST")
    COMPUTE_USER = os.getenv("COMPUTE_USER")
    COMPUTE_PASSWORD = os.getenv("COMPUTE_PASSWORD")

    # Email
    EMAIL_SENDER = os.getenv("EMAIL_SENDER")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
    EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")
