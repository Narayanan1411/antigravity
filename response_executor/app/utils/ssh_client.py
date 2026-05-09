import paramiko


class SSHClient:

    def run_command(self, host, username, password, command):

        ssh = paramiko.SSHClient()

        ssh.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        ssh.connect(
            hostname=host,
            username=username,
            password=password
        )

        stdin, stdout, stderr = ssh.exec_command(command)

        output = stdout.read().decode()
        error = stderr.read().decode()

        ssh.close()

        return {
            "output": output,
            "error": error
        }