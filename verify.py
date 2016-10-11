"""Verify that m of n unique and trusted signatures are present attesting to files.

Usage:
    $ python verify.py target-directory/ path/to/trusted-keyring.gpg unique-sigs
"""
import sys
import common #common.py

def _print_usage():
    print "Usage: python verify.py target-directory/ path/to/trusted-keyring.gpg unique-sigs"
    sys.exit()

def _main():
    if len(sys.argv) != 4:
        _print_usage()

    target_dir_name = sys.argv[1]
    trusted_keyring_filename = sys.argv[2]
    num_sigs_required = sys.argv[3]

    try:
        int(num_sigs_required)
    except ValueError:
        _print_usage()

    filehash_pairs, signatures = common.get_attestations(target_dir_name)
    sha256_string = common.sha256_digest_to_string(filehash_pairs)
    num_sigs = common.get_num_unique_trusted_sigs(
        sha256_string, signatures, trusted_keyring_filename)

    if num_sigs >= int(num_sigs_required):
        print "Attestation passed."
    else:
        print "Attestation failed."

if __name__ == '__main__':
    _main()
