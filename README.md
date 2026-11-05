# Auditable temporary artifact ingress

This repository candidate contains generic Python source and synthetic tests only.
It is not an application release, an installer, or an authorization to execute.

The intended launcher fetches `bootstrap.py` over authenticated HTTPS using a
specific full commit SHA, bounds the response length, checks SHA256 in memory,
and only then compiles and invokes it. No mutable branch URL, pipe to a shell,
compressed Console script, credential, private key or API fallback is required.

Target-specific configuration is supplied privately and separately hashed.
The program validates this configuration, target host public fingerprint,
root-owned paths, account absence and minimum host resources before provisioning.
It creates one non-sudo account, root-owned SSH key, bounded forced receiver and
fresh-user resource caps. It neither changes SSH daemon policy nor installs an
application. A later privately transferred artifact must match a separate exact
size/SHA256 before a bounded root child may execute it.

Failure is not permission to retry. Initial rollback locks only the just-created
UID if it still matches and stops only its owned slice. It retains evidence.
The private stage is responsible for its own reviewed rollback; hard kills or
unverified cleanup are UNKNOWN. Tests do not certify a real host deployment.

Dependencies: Python3.10+ standard library, Linux x86_64, existing OpenSSH server
with compatible public-key policy, systemd/cgroupv2, and standard user-management
utilities. No dependency is downloaded, installed or upgraded by this program.

No target address, account public key, private configuration, application source,
receipt, customer data, installer payload or operational log belongs here.
