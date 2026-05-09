from app.utils.ssh_client import SSHClient
from app.config.settings import Settings


class NetworkController:

    def __init__(self):
        self.ssh = SSHClient()

    def block_device(self, target_ip):

        check_command = (
            f"sudo iptables -C FORWARD "
            f"-i {Settings.HOTSPOT_INTERFACE} "
            f"-s {target_ip} -j DROP"
        )

        check = self.ssh.run_command(
            host=Settings.ROUTER_HOST,
            username=Settings.ROUTER_USER,
            password=Settings.ROUTER_PASSWORD,
            command=check_command
        )

        # Rule already exists
        if check["error"] == "":
            return {
                "status": "already_blocked",
                "target_ip": target_ip
            }

        add_command = (
            f"sudo iptables -A FORWARD "
            f"-i {Settings.HOTSPOT_INTERFACE} "
            f"-s {target_ip} -j DROP"
        )

        result = self.ssh.run_command(
            host=Settings.ROUTER_HOST,
            username=Settings.ROUTER_USER,
            password=Settings.ROUTER_PASSWORD,
            command=add_command
        )

        return {
            "status": "blocked",
            "target_ip": target_ip,
            "result": result
        }

    def unblock_device(self, target_ip):

        check_command = (
            f"sudo iptables -C FORWARD "
            f"-i {Settings.HOTSPOT_INTERFACE} "
            f"-s {target_ip} -j DROP"
        )

        check = self.ssh.run_command(
            host=Settings.ROUTER_HOST,
            username=Settings.ROUTER_USER,
            password=Settings.ROUTER_PASSWORD,
            command=check_command
        )

        # Rule does not exist
        if check["error"] != "":
            return {
                "status": "not_blocked",
                "target_ip": target_ip
            }

        remove_command = (
            f"sudo iptables -D FORWARD "
            f"-i {Settings.HOTSPOT_INTERFACE} "
            f"-s {target_ip} -j DROP"
        )

        result = self.ssh.run_command(
            host=Settings.ROUTER_HOST,
            username=Settings.ROUTER_USER,
            password=Settings.ROUTER_PASSWORD,
            command=remove_command
        )

        return {
            "status": "unblocked",
            "target_ip": target_ip,
            "result": result
        }