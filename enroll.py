"""Non-secret DEV enrollment profile. Publish only after owner review.
No application source, private keys, passwords, tokens or customer data.
Original five public artifacts remain unchanged.
"""
import hashlib,json,os,pwd,grp,stat,sys,time,urllib.request
from pathlib import Path
CONFIG = '{"actor":"victory-codex-dev","base":"/opt/victory-dev-20261107","expires":1794146400,"host_fingerprint":"SHA256:CEjXTH/WUNBa4mqgHp+I45zhrzw5OorWIq0lx86u+lA","latest_start":1794142800,"nonce":"db4802b8817bcebd9fd00bf95f64ce54","not_before":1794100617,"payload_bytes":67510,"payload_sha256":"ba1ab7d3e2d06bfd7ed8eaf04809a4be98ca8a9f18b1e6882d7a40708832fab7","public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC5R/PFt3tum/8nA+xuu049QZp08U1MLr8KxGcmAypq7"}'
CONFIG_SHA256 = '98e4ba523c123ddb6b4a58c91ef8254b6a8cf9cd39140f1246d1e42b8793d52b'
SOURCE_URL = 'https://raw.githubusercontent.com/yeuhoabinh3939-svg/victory-bootstrap-artifacts/9e8d84e181cd2f8e2c8eb15db997f0d62ddba577/bootstrap.py'
SOURCE_SHA256 = '7849aa31073318ccacaa3548388ffae74ce2058f22dc67492e6ed7d8a2ac5e9b'
SOURCE_BYTES = 11515

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

def readonly_gate(namespace,config):
    if os.geteuid()!=0:raise ValueError('ROOT_REQUIRED')
    # MA1/MA2 UNKNOWN: any residual account/path means STOP, never overwrite.
    for actor in ('victory-codex-dev',):
        for lookup in (pwd.getpwnam,grp.getgrnam):
            try:lookup(actor)
            except KeyError:pass
            else:raise ValueError('EXISTING_DEV_ACCOUNT_OR_GROUP_STOP_RECONCILE')
    for path in ('/opt/victory-dev-ma1','/opt/victory-dev-ma2','/opt/victory-dev-p2',
                 '/home/victory-codex-dev','/var/lib/victory-dev-ma1','/var/lib/victory-dev-ma2',
                 '/var/lib/victory-dev-p2','/opt/victory-dev-20261107','/var/lib/victory-dev-20261107'):
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
