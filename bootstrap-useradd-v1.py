"""Generic, temporary, hash-bound SSH artifact receiver. Standard library only.

Contains no host identity, login key, project code or customer configuration.
The caller supplies an audited configuration and its independent SHA256.
No downloads, installer, model, sudoers, sshd or firewall changes here.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def validate(raw, expected, now):
    if len(raw)>2048 or not re.fullmatch('[0-9a-f]{64}',expected) or sha(raw)!=expected:
        raise ValueError('CONFIG_HASH')
    c=json.loads(raw)
    required={'actor','base','public_key','host_fingerprint','payload_sha256','payload_bytes',
              'not_before','latest_start','expires','nonce'}
    if set(c)!=required:raise ValueError('CONFIG_FIELDS')
    if not isinstance(c['actor'],str) or not re.fullmatch('[a-z][a-z0-9-]{1,30}',c['actor']) or c['actor'] in ('root','daemon','nobody'):
        raise ValueError('ACTOR')
    if not isinstance(c['base'],str) or not re.fullmatch('/opt/[a-z][a-z0-9-]{1,48}',c['base']):raise ValueError('BASE')
    for name in ('payload_bytes','not_before','latest_start','expires'):
        if type(c[name]) is not int:raise ValueError('INTEGER')
    if not 1<=c['payload_bytes']<=4*1024**2:raise ValueError('SIZE')
    if not c['not_before']<=now<=c['latest_start'] or not 3000<=c['expires']-c['latest_start']<=86400 or c['expires']-c['not_before']>86400:
        raise ValueError('WINDOW')
    if not isinstance(c['nonce'],str) or not re.fullmatch('[a-f0-9]{32}',c['nonce']):raise ValueError('NONCE')
    if not isinstance(c['payload_sha256'],str) or not re.fullmatch('[a-f0-9]{64}',c['payload_sha256']):raise ValueError('PAYLOAD_HASH')
    if not isinstance(c['host_fingerprint'],str) or not re.fullmatch('SHA256:[A-Za-z0-9+/]{43}',c['host_fingerprint']):raise ValueError('HOST_FINGERPRINT')
    fields=c['public_key'].split()
    if len(fields)!=2 or fields[0]!='ssh-ed25519':raise ValueError('PUBLIC_KEY')
    blob=base64.b64decode(fields[1],validate=True)
    if len(blob)!=51 or blob[:19]!=b'\0\0\0\x0bssh-ed25519\0\0\0\x20':raise ValueError('PUBLIC_KEY')
    return c

def fresh(path):
    if path.exists() or path.is_symlink():raise ValueError('EXISTS_NO_REUSE')

def trusted(path):
    for node in (path,*path.parents):
        m=node.lstat()
        if stat.S_ISLNK(m.st_mode) or m.st_uid or m.st_mode&0o022:raise ValueError('ROOT_PATH')

def put(path,raw,mode):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f:
        if f.write(raw)!=len(raw):raise ValueError('SHORT_WRITE')
        f.flush();os.fsync(f.fileno())

def bounded(path,size):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        m=os.fstat(f.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_size>size:raise ValueError('FILE_METADATA')
        return f.read(size+1)

class CommandFailure(ValueError):
    def __init__(self, name, returncode, stderr):
        self.command=name
        self.returncode=returncode
        self.stderr_sha256=sha(stderr)
        self.stderr_bytes=len(stderr)
        self.stderr=stderr[:16384]
        self.stderr_truncated=len(stderr)>16384
        match=re.search(rb"unknown (?:configuration )?item [\x60'\"]([A-Z0-9_]{1,64})",stderr)
        self.diagnostic="UNKNOWN_CONFIG_ITEM_"+match.group(1).decode("ascii") if match else "NONZERO_COMMAND_EXIT"
        super().__init__("COMMAND_"+name+"_EXIT_"+str(returncode))

def ensure_useradd_defaults():
    raw=run(['/usr/sbin/useradd','-D']).stdout
    values=[line.split(b'=',1)[1].strip() for line in raw.splitlines() if line.startswith(b'CREATE_MAIL_SPOOL=')]
    if values!=[b'no']:
        raise ValueError('USERADD_NO_MAIL_DEFAULT_REQUIRED_NO_CONFIG_CHANGE')

def run(argv,timeout=15,check=True):
    r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        timeout=timeout,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
    if check and r.returncode:raise CommandFailure(Path(argv[0]).name,r.returncode,r.stderr)
    return r

def receiver(c):
    import resource
    signal.alarm(240)
    for kind,cap in ((resource.RLIMIT_AS,64*1024**2),(resource.RLIMIT_CPU,10),(resource.RLIMIT_FSIZE,5*1024**2)):
        resource.setrlimit(kind,(cap,cap))
    if os.geteuid()<1000 or os.environ.get('SSH_ORIGINAL_COMMAND')!='stage' or time.time()>=c['expires']-300:
        raise ValueError('RECEIVER_SCOPE')
    base=Path(c['base']);stage=Path('/home')/c['actor']/'stage'
    raw=sys.stdin.buffer.read(c['payload_bytes']+1)
    if len(raw)!=c['payload_bytes'] or sha(raw)!=c['payload_sha256']:raise ValueError('PAYLOAD_HASH')
    put(stage/'upload',raw,0o600)
    context={'uid':os.geteuid(),'nonce':c['nonce'],'ssh_connection':os.environ.get('SSH_CONNECTION','')}
    put(stage/'ready',json.dumps(context).encode(),0o600)
    end=min(time.monotonic()+180,time.monotonic()+c['expires']-time.time()-300)
    while time.monotonic()<end:
        if (base/'FAILURE_RECEIPT.json').exists():raise ValueError('PRIVATE_STAGE_FAILED')
        path=base/'bootstrap-ready.json'
        if path.exists():
            m=path.lstat()
            if m.st_uid or m.st_mode&0o022:raise ValueError('READY_AUTHORITY')
            result=bounded(path,16384)
            if json.loads(result).get('uid')!=os.geteuid():raise ValueError('READY_UID')
            sys.stdout.buffer.write(result);return
        time.sleep(.25)
    raise TimeoutError('PRIVATE_STAGE_TIMEOUT')

def revoke(c,uid,own_slice):
    import pwd
    if uid is None or pwd.getpwnam(c['actor']).pw_uid!=uid:return {'status':'UNKNOWN_NO_OWNED_UID_MUTATION'}
    run(['/usr/sbin/usermod','-e','1970-01-02',c['actor']])
    if own_slice:run(['/usr/bin/systemctl','stop','user-'+str(uid)+'.slice'])
    return {'status':'FRESH_ACCOUNT_EXPIRED_FILES_PRESERVED','uid':uid}

def provision(c,source):
    import pwd,grp,resource
    uid=None;own_slice=False;base=Path(c['base']);home=Path('/home')/c['actor'];owned=False;child=None
    deadline=time.monotonic()+2400
    def interrupted(signum,frame):raise TimeoutError('PROVISIONING_INTERRUPTED')
    signal.signal(signal.SIGALRM,interrupted);signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGHUP,interrupted)
    signal.alarm(2400)
    try:
        if os.geteuid()!=0 or os.uname().machine!='x86_64':raise ValueError('ROOT_X86_REQUIRED')
        resource.setrlimit(resource.RLIMIT_AS,(768*1024**2,768*1024**2))
        for parent in (base.parent,home.parent):trusted(parent)
        for path in (base,home):fresh(path)
        for lookup in (pwd.getpwnam,grp.getgrnam):
            try:lookup(c['actor'])
            except KeyError:pass
            else:raise ValueError('ACCOUNT_EXISTS')
        host=Path('/etc/ssh/ssh_host_ed25519_key.pub');trusted(host);m=host.lstat()
        if m.st_mode!=0o100644 or m.st_size>512:raise ValueError('HOST_PUBLIC_METADATA')
        fields=bounded(host,512).decode('ascii').split()
        if len(fields)<2 or fields[0]!='ssh-ed25519':raise ValueError('HOST_TYPE')
        actual='SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(fields[1],validate=True)).digest()).decode().rstrip('=')
        if actual!=c['host_fingerprint']:raise ValueError('WRONG_HOST')
        fs=os.statvfs(home.parent)
        mem={x.split(':')[0]:x.split(':')[1].split()[0] for x in Path('/proc/meminfo').read_text().splitlines() if ':' in x}
        if fs.f_bavail*fs.f_frsize<3*1024**3 or fs.f_favail<2048 or int(mem['MemAvailable'])<2*1024**2 or (os.cpu_count() or 0)<1:
            raise ValueError('RESOURCES')
        # Inverse plan prepared before first write: lock only exact fresh UID; retain unknown data.
        ensure_useradd_defaults()  # Read-only gate before the first VPS write.
        os.umask(0o022);base.mkdir(mode=0o755);owned=True
        run(['/usr/sbin/useradd','-U','-M','-l','-d',str(home),'-s','/bin/sh','-p','*','-K','SUB_UID_COUNT=0','-K','SUB_GID_COUNT=0','-K','UID_MIN=1000','-K','GID_MIN=1000',c['actor']])
        a=pwd.getpwnam(c['actor']);uid=a.pw_uid
        if uid<1000 or a.pw_gid==0 or set(os.getgrouplist(c['actor'],a.pw_gid))!={a.pw_gid}:raise ValueError('IDENTITY')
        slice_name='user-'+str(uid)+'.slice'
        for path in (Path('/etc/systemd/system')/(slice_name+'.d'),Path('/run/systemd/system')/(slice_name+'.d'),Path('/sys/fs/cgroup/user.slice')/slice_name):fresh(path)
        run(['/usr/bin/systemctl','start',slice_name]);own_slice=True
        run(['/usr/bin/systemctl','set-property','--runtime',slice_name,'CPUQuota=100%','MemoryMax=1G','TasksMax=64'])
        home.mkdir(mode=0o755);(home/'.ssh').mkdir(mode=0o755)
        stage=home/'stage';stage.mkdir(mode=0o700);os.chown(stage,uid,a.pw_gid)
        policy=run(['/usr/sbin/sshd','-T','-C','user='+c['actor']+',host=localhost,addr=127.0.0.1']).stdout.decode()
        for line in ('forcecommand none','chrootdirectory none','pubkeyauthentication yes','authorizedkeyscommand none','trustedusercakeys none','permituserenvironment no','strictmodes yes'):
            if line not in policy.splitlines():raise ValueError('EXISTING_POLICY_UNSUPPORTED')
        lookup=[x for x in policy.splitlines() if x.startswith('authorizedkeysfile ')]
        if lookup not in (['authorizedkeysfile .ssh/authorized_keys'],['authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2']):raise ValueError('KEY_LOOKUP_UNSUPPORTED')
        put(base/'receive.py',('CFG='+repr(c)+'\n').encode()+source,0o644)
        expiry=time.strftime('%Y%m%d%H%M%SZ',time.gmtime(c['expires']))
        key=('restrict,expiry-time="'+expiry+'",command="/usr/bin/python3 -I -B '+str(base/'receive.py')+' receive" '+c['public_key']+'\n').encode()
        put(home/'.ssh/authorized_keys',key,0o644)
        boot={'uid':uid,'gid':a.pw_gid,'nonce':c['nonce'],'initial_key_sha256':sha(key),'owned_slice':own_slice}
        put(base/'BOOTSTRAP_RECEIPT.json',json.dumps(boot).encode(),0o644)
        signal.signal(signal.SIGHUP,signal.SIG_IGN)
        print('CHANNEL_READY '+c['nonce'],flush=True)
        sys.stdin=open(os.devnull);sys.stdout=sys.stderr=open(os.devnull,'w')
        until=min(deadline,time.monotonic()+600)
        while time.monotonic()<until:
            if (stage/'ready').exists():break
            time.sleep(.25)
        else:raise TimeoutError('UPLOAD_WAIT_TIMEOUT')
        context=json.loads(bounded(stage/'ready',512));raw=bounded(stage/'upload',c['payload_bytes']+1)
        if context.get('uid')!=uid or context.get('nonce')!=c['nonce'] or len(raw)!=c['payload_bytes'] or sha(raw)!=c['payload_sha256']:
            raise ValueError('ROOT_STAGE_BINDING')
        header=('BOOTSTRAP_CONFIG='+repr(c)+'\nBOOTSTRAP_CONTEXT='+repr(context)+'\nBOOTSTRAP_RECEIPT='+repr(boot)+'\n').encode()
        put(base/'private-stage.py',header+raw,0o600)
        fd=os.open(base/'private-stage.log',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as log:
            child=subprocess.Popen(['/usr/bin/python3','-I','-B',str(base/'private-stage.py')],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
            if child.wait(timeout=max(1,deadline-time.monotonic()))!=0:raise ValueError('PRIVATE_STAGE_FAILED')
        signal.alarm(0)
    except BaseException as error:
        signal.alarm(180)
        if child is not None and child.poll() is None:
            os.killpg(child.pid,signal.SIGTERM)
            try:child.wait(timeout=150)
            except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=15)
        result={'status':'FAIL_OR_UNKNOWN_NO_RETRY','type':type(error).__name__,'code':str(error) if isinstance(error,(ValueError,TimeoutError)) else 'OS_ERROR'}
        if isinstance(error,CommandFailure):
            result.update(command=error.command,subprocess_returncode=error.returncode,diagnostic=error.diagnostic,stderr_sha256=error.stderr_sha256)
        try:result['revoke']=revoke(c,uid,own_slice)
        except BaseException:result['revoke']='UNKNOWN_PRESERVE'
        if owned:
            try:
                if isinstance(error,CommandFailure):
                    put(base/'COMMAND_FAILURE.stderr',error.stderr,0o600)
                    result.update(stderr_bytes=error.stderr_bytes,stderr_truncated=error.stderr_truncated,stderr_file='COMMAND_FAILURE.stderr')
                put(base/'BOOTSTRAP_FAILURE.json',json.dumps(result).encode(),0o644)
            except BaseException:pass
        signal.alarm(0)
        print(json.dumps(result),flush=True)  # Filtered diagnostics; raw stderr stays root-only.
        raise

if __name__=='__main__':
    if sys.argv[1:]==['receive']:receiver(CFG)
    else:
        config=validate(sys.argv[1].encode('ascii'),sys.argv[2],time.time())
        provision(config,SOURCE)
