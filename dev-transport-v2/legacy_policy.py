"""Exact legacy command function, extracted from the sealed historical policy."""
SFTP_COMMANDS = {"internal-sftp", "/usr/lib/openssh/sftp-server"}
ACTIONS = {"status", "verify", "native", "install", "receipt", "rollback-files", "run-dev"}
def command(original):
    if original in SFTP_COMMANDS:
        return 'sftp'
    if original in ACTIONS or original == 'activate':
        return original
    raise ValueError('FIXED_COMMAND_ONLY')
