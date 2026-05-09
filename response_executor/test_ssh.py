from app.utils.ssh_client import SSHClient
from app.config.settings import Settings

ssh = SSHClient()

result = ssh.run_command(
    host=Settings.COMPUTE_HOST,
    username=Settings.COMPUTE_USER,
    password=Settings.COMPUTE_PASSWORD,
    command="hostname"
)

print(result)