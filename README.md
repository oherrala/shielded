# Shielded Memory

A crate drawing inspiration and parts of the documentation from OpenBSD's /
OpenSSH's
[commit](https://github.com/openbsd/src/commit/707316f931b35ef67f1390b2a00386bdd0863568).

This crate implements a Shielded Memory providing protection at rest for
secrets kept in memory against speculation and memory sidechannel attacks
like Spectre, Meltdown, Rowhammer and Rambleed. The contents of the memory
are encrypted when [`Shielded`](struct.Shielded.html) is constructed, then
decrypted on demand and encrypted again after memory is no longer needed.

The memory protection is achieved by generating a 16kB secure random prekey
which is then hashed with SHA512 to construct an encryption key for
ChaCha20-Poly1305 cipher. This cipher is then used to encrypt the contents of
memory in-place.

Attackers must recover the entire prekey with high accuracy before they can
attempt to decrypt the shielded memory, but the current generation of attacks
have bit error rates that, when applied cumulatively to the entire prekey, make
this unlikely.
