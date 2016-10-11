# multi-sig-check-demo

Attest to a snapshot of files using m of n trusted PGP signatures.

WARNING: Not (yet) suitable for use in a production environment.

The `attest.py` script can be used by multiple PGP key holders to attest to the
state of a target directory. They should do so in series, passing the
`attestation.txt` file generated on to the next signer.

The `verify.py` script checks how many times the attestation has been signed
by unique keys in a trusted keyring. If m required keys out of the n keys in
the keyring have been used for signing, attestation passes.

## Setup

A verifier will need to import the all of trusted PGP public keys into a GPG
keychain file. This keychain file must remain secure from alteration
by attackers, but will not be cryptographically compromised if merely read by an
attacker. (You may wish to keep it secret for OPSEC reasons to avoid betraying
the private key holders.)

## Usage

### Generating an attestation

    $ python attest.py target-directory/ gpg-key-id

If an `attestation.txt` already exists in the parent directory, this will
generate SHA-256 hashes of all files and files in sub-directories, and verify
that this matches what is currently in the `attestation.txt` file. If the
file hashes do not match up completely (excluding `attestation.txt`), an error
will be output. Otherwise, it will append a PGP signature of the hashes to the
end of `attestation.txt` using the private key corresponding to the specified
GPG key id.

If `attestation.txt` does not yet exist, it will be created in the target
directory.

In order to be completed successfully, GPG **MUST** be configured to permit
TTY input. (See: `gpg.conf`, which MAY be located at `~/.gnupg/gpg.conf`.)

### Verifying an attestation

    $ python verify.py target-directory/ path/to/trusted-keyring.gpg unique-sigs

Where "unique-sigs" is an integer value less than or equal to the total number
of public keys listed in `trusted-keyring.gpg`, indicating how many
unique and trusted signatures are required in order to pass verification.
If verification passes, the string "Attestation passed.\n" is written to
STDOUT; otherwise, the string "Attestation failed.\n" is written to STDOUT.

## Requirements

* `gpg` v2
* `python` 2.7+
* `openssl` command-line program
* `find` UNIX program

## Examples

See the [examples](examples/osx-config-check-master) files included for an
example. They were generated with the following commands from Bash shell.

To create a keyring of trusted keys:
```
    $ gpg --export demo1@example.com demo2@example.com demo3@example.com > trusted.gpg
    $ gpg --no-default-keyring --keyring=./examples/trusted-keyring.gpg --import trusted.gpg
    gpg: keyring `./examples/trusted-keyring.gpg' created
    gpg: key C02C7370: public key "demo1 <demo1@example.com>" imported
    gpg: key E2568906: public key "demo2 <demo2@example.com>" imported
    gpg: key CA81A006: public key "demo3 <demo3@example.com>" imported
    gpg: Total number processed: 3
    gpg:               imported: 3  (RSA: 3)
```

```
    $ python attest.py examples/osx-config-check-master/ demo1@example.com
    $ python verify.py examples/osx-config-check-master/ examples/trusted-keyring.gpg 2
    $ python attest.py examples/osx-config-check-master/ demo2@example.com
    $ python verify.py examples/osx-config-check-master/ examples/trusted-keyring.gpg 2
```

Output:
```
Attestation failed.
Attestation passed.
```

This example was generated using 3 keypairs corresponding to imaginary users
demo1@example.com, demo2@example.com, and demo3@example.com. You will need to
import the 3 private keys, included in the [examples](examples/) directory, into
your GPG keychain in order to reproduce these results. The passphrase for each
of the private keys is "password".

## Helpful GPG links

* http://superuser.com/questions/639853/gpg-verifying-signatures-without-creating-trust-chain/
* https://www.gnupg.org/gph/en/manual/x135.html
* http://superuser.com/questions/399938/how-to-create-additional-gpg-keyring
* http://security.stackexchange.com/questions/84280/short-openpgp-key-ids-are-insecure-how-to-configure-gnupg-to-use-long-key-ids-i
