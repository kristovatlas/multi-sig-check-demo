"""GPG sign an attestation of files.

Usage:
    $ python attest.py target-directory/ gpg-key-id

Todos:
    * Clean up assertions and other file handling
"""
import sys
import common #common.py

def _print_usage():
    print "Usage: python attest.py target-directory/ gpg-key-id"
    sys.exit()

def _main():
    if len(sys.argv) != 3:
        _print_usage()

    target_dir_name = sys.argv[1]
    key_id = sys.argv[2]

    filehash_pairs = []
    signatures = []

    pairs = common.get_sha256_digests(target_dir_name)
    sha256_string = common.sha256_digest_to_string(pairs)

    #Attempt to compare to previous attestation.txt
    try:
        filehash_pairs, signatures = common.get_attestations(target_dir_name)

        assert len(filehash_pairs) > 0
        assert len(signatures) > 0

        if not common.are_sigs_valid(sha256_string, signatures):
            sys.exit(("Error: One or more of the signatures in %s do not match "
                      "the file digests.") % common.ATTESTATION_FILENAME)

    except common.AttestationFileNotPresentError:
        pass

    if len(filehash_pairs) > 0:
        if not common.are_digests_equal(filehash_pairs, pairs):
            sys.exit(("Error: File digests do not match previous ones "
                      "generated and placed in %s") %
                     common.ATTESTATION_FILENAME)


    signature = common.get_string_sig(sha256_string, key_id)
    assert signature != ''

    if signature in signatures:
        #in general, this is not likely to be triggered since signatures are
        #not usually deterministically generated, so multiple signatures
        #produced on the same target file with the same key will not be equal.
        sys.exit("Error: This signature has already been added! No duplicates "
                 "allowed.")
    signatures.append(signature)

    #overwrite attestation.txt
    common.write_attestation_to_file(sha256_string, signatures, target_dir_name)

if __name__ == "__main__":
    _main()
