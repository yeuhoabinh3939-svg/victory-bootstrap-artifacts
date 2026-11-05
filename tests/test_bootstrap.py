"""Synthetic identities only. No network, account creation or root operations."""
import ast,base64,hashlib,importlib.util,json,os,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('candidate_bootstrap',ROOT/'bootstrap.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)

def config():
    # A fabricated public wire value, never a real account identity/private key.
    wire=b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+b'\x01'*32
    return {'actor':'devfixture','base':'/opt/devfixture','public_key':'ssh-ed25519 '+base64.b64encode(wire).decode(),
        'host_fingerprint':'SHA256:'+'A'*43,'payload_sha256':'a'*64,'payload_bytes':123,
        'not_before':100,'latest_start':200,'expires':4000,'nonce':'b'*32}

class Validate(unittest.TestCase):
    def check(self,c,now=150):
        raw=json.dumps(c,separators=(',',':')).encode();return b.validate(raw,b.sha(raw),now)
    def test_valid(self):self.assertEqual(self.check(config()),config())
    def test_changed_config_rejected(self):
        raw=json.dumps(config()).encode()
        with self.assertRaises(ValueError):b.validate(raw+b' ','0'*64,150)
    def test_invalid_actors(self):
        for value in ('root','nobody','../other','-option','a'*32,'x/y'):
            with self.subTest(value=value),self.assertRaises(ValueError):self.check({**config(),'actor':value})
    def test_invalid_base(self):
        for value in ('/etc/ssh','/opt/../etc','/opt/a/b','relative','/opt/-bad'):
            with self.subTest(value=value),self.assertRaises(ValueError):self.check({**config(),'base':value})
    def test_size_limits(self):
        for value in (0,4*1024**2+1,True,'123'):
            with self.subTest(value=value),self.assertRaises(ValueError):self.check({**config(),'payload_bytes':value})
    def test_time_gate(self):
        for now in (99,201,9999):
            with self.subTest(now=now),self.assertRaises(ValueError):self.check(config(),now)
    def test_insufficient_cleanup_window(self):
        with self.assertRaises(ValueError):self.check({**config(),'expires':250})
    def test_excessive_lifetime(self):
        with self.assertRaises(ValueError):self.check({**config(),'expires':1000000})
    def test_invalid_nonce_hash_and_host(self):
        for name,value in (('nonce','x'*32),('payload_sha256','a'*63),('host_fingerprint','http://untrusted')):
            with self.subTest(name=name),self.assertRaises(ValueError):self.check({**config(),name:value})
    def test_invalid_key(self):
        for key in ('ssh-rsa wrong','ssh-ed25519 invalid','ssh-ed25519 AA==','ssh-ed25519 AA== comment'):
            with self.subTest(key=key),self.assertRaises(ValueError):self.check({**config(),'public_key':key})
    def test_extra_field_denied(self):
        with self.assertRaises(ValueError):self.check({**config(),'sudo':True})

class FileAndRollback(unittest.TestCase):
    def test_exclusive_no_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'evidence';p.write_bytes(b'keep')
            # Windows adapter covers exclusive-write IO, not Linux nofollow semantics.
            with patch.object(os,'O_NOFOLLOW',getattr(os,'O_NOFOLLOW',0),create=True):
                with self.assertRaises(FileExistsError):b.put(p,b'new',0o600)
            self.assertEqual(p.read_bytes(),b'keep')
    def test_new_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'evidence'
            with patch.object(os,'O_NOFOLLOW',getattr(os,'O_NOFOLLOW',0),create=True):b.put(p,b'new',0o600)
            self.assertEqual(p.read_bytes(),b'new')
    def test_fresh_path_refuses_existing(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):b.fresh(Path(td))
    def test_reassigned_uid_never_changed(self):
        calls=[];fake=types.SimpleNamespace(getpwnam=lambda name:types.SimpleNamespace(pw_uid=1002))
        with patch.dict(sys.modules,{'pwd':fake}),patch.object(b,'run',lambda argv:calls.append(argv)):
            result=b.revoke(config(),1001,True)
        self.assertEqual(calls,[]);self.assertIn('UNKNOWN',result['status'])
    def test_owned_account_only(self):
        calls=[];fake=types.SimpleNamespace(getpwnam=lambda name:types.SimpleNamespace(pw_uid=1001))
        with patch.dict(sys.modules,{'pwd':fake}),patch.object(b,'run',lambda argv:calls.append(argv)):
            b.revoke(config(),1001,False)
        self.assertEqual(len(calls),1);self.assertEqual(calls[0][-1],'devfixture')
    def test_owned_slice_only(self):
        calls=[];fake=types.SimpleNamespace(getpwnam=lambda name:types.SimpleNamespace(pw_uid=1001))
        with patch.dict(sys.modules,{'pwd':fake}),patch.object(b,'run',lambda argv:calls.append(argv)):
            b.revoke(config(),1001,True)
        self.assertEqual(calls[-1],['/usr/bin/systemctl','stop','user-1001.slice'])

class SourceBoundary(unittest.TestCase):
    def test_preflight_precedes_first_write(self):
        source=(ROOT/'bootstrap.py').read_text();start=source.index('def provision(');source=source[start:]
        first=source.index('base.mkdir(')
        for gate in ('WRONG_HOST','RESOURCES','ACCOUNT_EXISTS','trusted(parent)','fresh(path)'):
            self.assertLess(source.index(gate),first)
    def test_configuration_verified_before_provision(self):
        tree=ast.parse((ROOT/'bootstrap.py').read_text());main=tree.body[-1]
        text=ast.unparse(main);self.assertLess(text.index('validate('),text.index('provision('))
    def test_no_download_model_or_security_policy_writer(self):
        tree=ast.parse((ROOT/'bootstrap.py').read_text())
        # The module's explanatory docstring names prohibited operations; it is not code.
        if isinstance(tree.body[0],ast.Expr) and isinstance(tree.body[0].value,ast.Constant):tree.body.pop(0)
        strings=[n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
        for forbidden in ('sshd_config','firewall','sudoers','api.openai.com','auth.json','victory-runner'):
            self.assertFalse(any(forbidden in x for x in strings))
    def test_private_stage_hash_before_snapshot_and_launch(self):
        source=(ROOT/'bootstrap.py').read_text();start=source.index('context=json.loads');source=source[start:]
        self.assertLess(source.index("sha(raw)!=c['payload_sha256']"),source.index("put(base/'private-stage.py'"))
        self.assertLess(source.index("put(base/'private-stage.py'"),source.index('subprocess.Popen('))

if __name__=='__main__':unittest.main(verbosity=2)
