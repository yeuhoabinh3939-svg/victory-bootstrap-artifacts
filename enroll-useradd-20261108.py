"""Non-secret DEV enrollment profile. Publish only after owner review.
No application source, private keys, passwords, tokens or customer data.
Original five public artifacts remain unchanged.
"""
import hashlib,json,os,pwd,grp,stat,sys,time,urllib.request
from pathlib import Path
CONFIG = '{"actor":"victory-codex-dev","base":"/opt/victory-dev-20261108-u1","expires":1794146400,"host_fingerprint":"SHA256:CEjXTH/WUNBa4mqgHp+I45zhrzw5OorWIq0lx86u+lA","latest_start":1794142800,"nonce":"2208737a47390d84f3c67e219679dbd5","not_before":1794106950,"payload_bytes":67543,"payload_sha256":"b48d99394636ad4bc96034d517f6e029c8d2bccd48e8c436e99be27ed9c3511b","public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC5R/PFt3tum/8nA+xuu049QZp08U1MLr8KxGcmAypq7"}'
CONFIG_SHA256 = 'a4d627ba243d61c12803ec8940898b6f4e3ee67f87b481a8de151d0dcc1e4bd2'
SOURCE_URL = 'https://raw.githubusercontent.com/yeuhoabinh3939-svg/victory-bootstrap-artifacts/4e47894beebb140a52b0ef247059887723be4eeb/bootstrap-useradd-v1.py'
SOURCE_SHA256 = '7a98578b4103ce977eec1fbd8d64af3707c308b98efba54885016314cedc4f89'
SOURCE_BYTES = 13041

def verified_source(fetch=urllib.request.urlopen):
    with fetch(SOURCE_URL,timeout=20) as response:
        raw=response.read(SOURCE_BYTES+1)
        if response.geturl()!=SOURCE_URL or len(raw)!=SOURCE_BYTES or hashlib.sha256(raw).hexdigest()!=SOURCE_SHA256:
            raise ValueError('IMMUTABLE_SOURCE_HASH_OR_SIZE_OR_URL')
    return raw

def prepare(raw,now=None):
    # This function has no writes. Compile/validate before any provisioning.
    namespace={'__name__':'audited_bootstrap','SOURCE':raw}
    exec(compile(raw,SOURCE_URL,'exec'),namespace)
    config=namespace['validate'](CONFIG.encode(),CONFIG_SHA256,time.time() if now is None else now)
    return namespace,config

PRESERVED_FAILURE_SHA256 = 'ee01b2ee4e528046c87cdda9537c999923589ae0acae90eef22a9384310a05a1'
def preserved_failure_gate(namespace, old_base=Path('/opt/victory-dev-20261107')):
    # Read-only reconciliation: known failed namespace is preserved, never reused.
    namespace['trusted'](old_base)
    m=old_base.lstat()
    if not stat.S_ISDIR(m.st_mode) or m.st_uid!=0 or stat.S_IMODE(m.st_mode)!=0o755:
        raise ValueError('PRESERVED_BASE_METADATA_UNKNOWN')
    if {p.name for p in old_base.iterdir()}!={'BOOTSTRAP_FAILURE.json'}:
        raise ValueError('PRESERVED_BASE_UNKNOWN_MEMBERS_STOP')
    receipt=old_base/'BOOTSTRAP_FAILURE.json'
    namespace['trusted'](receipt)
    m=receipt.lstat()
    if not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or m.st_nlink!=1 or m.st_size!=142 or stat.S_IMODE(m.st_mode)!=0o644:
        raise ValueError('PRESERVED_FAILURE_METADATA_UNKNOWN')
    raw=namespace['bounded'](receipt,142)
    if len(raw)!=142 or hashlib.sha256(raw).hexdigest()!=PRESERVED_FAILURE_SHA256:
        raise ValueError('PRESERVED_FAILURE_HASH_UNKNOWN')

def readonly_gate(namespace,config):
    if os.geteuid()!=0:raise ValueError('ROOT_REQUIRED')
    preserved_failure_gate(namespace)
    # MA1/MA2 UNKNOWN: any residual account/path means STOP, never overwrite.
    for actor in ('victory-codex-dev',):
        for lookup in (pwd.getpwnam,grp.getgrnam):
            try:lookup(actor)
            except KeyError:pass
            else:raise ValueError('EXISTING_DEV_ACCOUNT_OR_GROUP_STOP_RECONCILE')
    for path in ('/opt/victory-dev-ma1','/opt/victory-dev-ma2','/opt/victory-dev-p2',
                 '/home/victory-codex-dev','/var/lib/victory-dev-ma1','/var/lib/victory-dev-ma2',
                 '/var/lib/victory-dev-p2','/opt/victory-dev-20261108-u1','/var/lib/victory-dev-20261108-u1'):
        namespace['fresh'](Path(path))
    # The original source also checks host pin, resources and root paths before writes.
    # Verify the effective existing user policy before useradd, without changing it.
    policy=namespace['run'](['/usr/sbin/sshd','-T','-C',
        'user='+config['actor']+',host=localhost,addr=127.0.0.1']).stdout.decode().splitlines()
    for line in ('forcecommand none','chrootdirectory none','pubkeyauthentication yes',
                 'authorizedkeyscommand none','trustedusercakeys none','permituserenvironment no','strictmodes yes'):
        if line not in policy:raise ValueError('EXISTING_POLICY_UNSUPPORTED_STOP')
    lookup=[line for line in policy if line.startswith('authorizedkeysfile ')]
    if lookup not in (['authorizedkeysfile .ssh/authorized_keys'],['authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2']):
        raise ValueError('EXISTING_KEY_LOOKUP_UNSUPPORTED_STOP')

def main():
    raw=verified_source()
    namespace,config=prepare(raw)
    readonly_gate(namespace,config)
    print('DEV_ENROLLMENT_READONLY_GATE_COMPLETE',flush=True)
    namespace['provision'](config,raw)

if __name__=='__main__':main()
