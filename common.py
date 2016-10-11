"""Functions and constants used by both attest.py and verify.py.

Todos:
    * There may be TOCTOU issues to exploit by using find -exec openssl dgst
    * There may be TOCTOU issues to exploit because of the use of tempfile files
        which can be modified by other applications (implement file lock?)
    * Is there a standardized number of dashes in PGP headers?
"""
from sys import exit as sys_exit
import re
from subprocess import Popen, PIPE, STDOUT
from os.path import expanduser, relpath, join
from os import access, R_OK
import itertools
from tempfile import NamedTemporaryFile

ATTESTATION_FILENAME = 'attestation.txt'
EXPECTED_SHA256_LINE = r"^SHA256\(([^\)]+)\)=\s+([0-9A-Fa-f]+)\n?$"
PGP_SIGNATURE_HEADER = r"^-----BEGIN PGP SIGNATURE-----\n?$"
PGP_SIGNATURE_FOOTER = r"^-----END PGP SIGNATURE-----\n?$"
GPG_GOOD_SIGNATURE_USERNAME = r"^gpg: Good signature from \"([^\"]+)\""
GPG_GOOD_SIGNATURE_LONG_KEY = r"^gpg:\s+using.*\s+([0-9A-Fa-f]{16})\s*$"

ENABLE_DEBUG_PRINT = False

class AttestationFileNotPresentError(Exception):
    """Attestation file not present."""
    pass

class MalformedPGPSignature(Exception):
    """Bad PGP signature"""
    pass

def run_command(command):
    """Runs a shell command and returns stdout."""
    process = Popen(command, stdout=PIPE, stderr=STDOUT, shell=True)
    stdoutdata, stderrdata = process.communicate()
    dprint("STDOUT: '%s' STDERR: '%s'" % (stdoutdata, stderrdata))
    return stdoutdata

def standardize_filename(top_level_dir, filename):
    """Standardize the location of a file no matter where the top is located.

    For example, both:
        /foo/bar/dir/1.txt given top directory /foo/bar/
        /apocalypse/now/bar/dir/1.txt given top directory /apocaplyse/now/bar/
    Should resolve to:
        dir/1.txt
    """
    return relpath(filename, top_level_dir)


def build_find_command(target_dir_name, filenames_to_exclude):
    """Generate the `find` command string.
    Args:
        target_dir_name (str): The target directory name, with an absolute path
            or path relative to the current working directory. May start with
            "~/" to refer to current user's home directory.
        filenames_to_exclude (List[str]): A list of filenames that should not
            be hashed, such as ["myfile.txt", "foobar.bin"]

    Returns: str: The `find` command to be executed
    """
    if target_dir_name.endswith('/'):
        target_dir_name = target_dir_name.rstrip('/')

    #for shells that support "~/"
    if target_dir_name.startswith("~/"):
        target_dir_name = expanduser(target_dir_name)

    command = "find '%s' -type f " % target_dir_name
    for filename in filenames_to_exclude:
        command += "! -name '%s' " % filename

    command += '-exec openssl dgst -sha256 {} \\;'
    dprint("Command: '%s'" % command)
    return command


def build_sign_command(input_filename, key_id, output_filename):
    """Generate the `gpg` command to sign the specified file."""
    command = (("gpg --detach-sign --sign "
                "--yes --armor "
                "--local-user %s "
                "--output '%s' '%s'") %
               (key_id, output_filename, input_filename))
    dprint("Command: '%s'" % command)
    return command


def build_verify_command(signature_filename, target_filename):
    """Generate the `gpg` command to verify a signature is correct.

    Args:
        signature_filename (str): Temporary file storing the signature to
            verify.
        target_filename (str): Temporary file storing the file match against
            the signature.
    """
    command = "gpg --verify '%s' '%s'" % (signature_filename, target_filename)
    dprint("Command: '%s'" % command)
    return command

def build_verify_trust_command(trusted_keyring_filename, signature_filename,
                               target_filename):
    """Generate the `gpg` command to verify a signature is correct and trusted.

    """
    command = (("gpg --no-default-keyring --keyring '%s' "
                "--keyserver-options -no-auto-key-retrieve "
                "--keyid-format long "
                "--verify '%s' '%s'") %
               (trusted_keyring_filename, signature_filename, target_filename))
    dprint("Command: '%s'" % command)
    return command


def are_digests_equal(pairs1, pairs2):
    """Returns: Whether the lists of digests are equivalent."""
    if len(pairs1) != len(pairs2):
        return False

    for pair1, pair2 in itertools.izip(pairs1, pairs2):
        if pair1[0] != pair2[0] or pair2[1] != pair2[1]:
            return False

    return True


def get_sha256_digests(target_dir_name, filenames_to_exclude=None):
    """Generates pairs of filenames and sha256 hashes for specified directory.

    This uses the `openssl` and `find` commands. If any output in the results
    does not meet the expected format, a ValueError exception is raised.

    Returns: List of pairs: [filename (str), sha256hash (str)]
    """
    if filenames_to_exclude is None:
        filenames_to_exclude = []

    if not access(target_dir_name, R_OK):
        sys_exit("Could not read one or more files in '%s'" % target_dir_name)

    if ATTESTATION_FILENAME not in filenames_to_exclude:
        filenames_to_exclude.append(ATTESTATION_FILENAME)

    verify_command = build_find_command(target_dir_name, filenames_to_exclude)

    contents = run_command(verify_command)
    prev_line = '' #only used for error messages
    pairs = []
    for line in contents.split("\n"):
        pair = get_pair_from_line(target_dir_name, line, prev_line)
        if pair is not None:
            pairs.append(pair)

        prev_line = line.rstrip()
    return pairs

def get_pair_from_line(target_dir_name, line, prev_line='', standardize=True,
                       raise_error=True):
    """Extract the filename hash from the results of `find` and `openssl dgst`

    Args:
        target_dir_name (str): The target directory being attested to.
        line (str): A line from attestation.txt or the results of the `find`
            command.
        prev_line (str): The previous line, for reference in debugging output.
        stanrdize (bool): Whether file references in `line` need to be
            standardized with reference to `target_dir_name`, or have already
            been standarized. Output from `find` has not previously been
            standardized, but input from `attestation.txt` has.
        raise_error (bool): Whether to raise an exception if the line doesn't
            match the expected format.

    Returns: pair [filename, hash] or None if line was empty.

    Raises: ValueError if result is not expected format and `raise_error` is
        True.
    """
    if line.isspace() or line == '':
        return None
    match = re.search(EXPECTED_SHA256_LINE, line)
    if match is None or len(match.groups()) != 2:
        if raise_error:
            raise ValueError(("Line containing '%s' does not match "
                              "expected format. Previous line: '%s'") %
                             (line, prev_line))
        else:
            return None

    file_path = match.group(1)
    if standardize:
        file_path = standardize_filename(target_dir_name, file_path)

    sha256_hash = match.group(2)
    return [file_path, sha256_hash]


def sha256_digest_to_string(pairs):
    """Convert pairs of filenames and hashes to expected string format."""
    ret = ''
    for pair in pairs:
        filename = pair[0]
        sha256_hash = pair[1]
        ret += "SHA256(%s)= %s\n" % (filename, sha256_hash)
    return ret


def get_string_sig(string, key_id):
    """Generate a PGP signature of a string using the specified key_id.
    """
    result = None

    with NamedTemporaryFile() as temp_in:
        temp_in.write(string)
        temp_in.flush()
        input_filename = temp_in.name
        dprint("File to store string: '%s'" % input_filename)

        with NamedTemporaryFile() as temp_out:
            output_filename = temp_out.name
            dprint("File to store signature: '%s'" % output_filename)

            cmd = build_sign_command(input_filename, key_id, output_filename)
            run_command(cmd)
            result = temp_out.read()

    dprint("Signature for string: '%s'" % result)
    return result

def write_attestation_to_file(sha256_string, signatures, target_dir_name):
    """Write the attestation to file."""
    destination = join(target_dir_name, ATTESTATION_FILENAME)
    with open(destination, 'w') as dest:
        dest.write("%s\n" % sha256_string)
        for signature in signatures:
            dest.write("%s\n" % signature)

def get_attestations(target_dir_name):
    """Get sha256 hashes and PGP signatures from attestation file.

    Raises:
        `AttestationFileNotPresentError` if attestations.txt doesn't exist yet.
        `MalformedPGPSignature`: If the PGP signature cannot be parsed.

    Returns: [pairs, signatures] where pairs is a list of [filename, hashes] and
        signatures is a list of strings.
    """
    destination = join(target_dir_name, ATTESTATION_FILENAME)
    lines = []

    if not access(destination, R_OK):
        raise AttestationFileNotPresentError

    with open(destination, 'r') as source:
        lines = source.readlines()
    assert len(lines) > 0

    pairs = []
    signatures = []
    pgp_sig_buffer = ''
    in_pgp_message_body = False

    for line in lines:
        pair = get_pair_from_line(target_dir_name, line, prev_line='',
                                  standardize=False, raise_error=False)
        if pair is not None:
            pairs.append(pair)
        else:
            if in_pgp_message_body:
                if re.search(PGP_SIGNATURE_FOOTER, line) is not None:
                    pgp_sig_buffer += line
                    signatures.append(pgp_sig_buffer)
                    pgp_sig_buffer = ''
                    in_pgp_message_body = False

                elif re.search(PGP_SIGNATURE_HEADER, line) is not None:
                    raise MalformedPGPSignature
                else:
                    pgp_sig_buffer += line
            else:
                if re.search(PGP_SIGNATURE_HEADER, line) is not None:
                    pgp_sig_buffer += line
                    in_pgp_message_body = True

                elif re.search(PGP_SIGNATURE_FOOTER, line) is not None:
                    raise MalformedPGPSignature

    return [pairs, signatures]

def are_sigs_valid(sha256_string, signatures):
    """Verifies that all of the PGP signatures match the string.

    This does not verify that the signatures are trusted, only that they match
    the string.

    Args:
        sha256_string (str): The properly formatted list of SHA256 hashes of
            files that has been signed, allegedly.
        signatures (List[str]): PGP messages represnting signatures of
            `sha256_string`.

    Returns: bool: Whether all signatures passed or some failed.
    """
    assert len(signatures) > 0

    dprint("signed string: '%s'" % sha256_string)

    with NamedTemporaryFile() as sha256_tmp_file:
        sha256_tmp_file.write(sha256_string)
        sha256_tmp_file.flush()
        target_filename = sha256_tmp_file.name
        dprint("File to store string: '%s' string: '%s'" % (target_filename,
                                                            sha256_string))

        for index, signature in enumerate(signatures):
            dprint("Signature to verify: '%s'" % signature)
            good_signature = False
            with NamedTemporaryFile() as sig_tmp_file:
                dprint("Signature to write to tmp file: '%s'" % signature)
                sig_tmp_file.write(signature)
                sig_tmp_file.flush()
                signature_filename = sig_tmp_file.name
                dprint("File to store signature #%d: '%s'" %
                       (index + 1, signature_filename))

                cmd = build_verify_command(signature_filename, target_filename)
                stdout = run_command(cmd)
                for line in stdout.split("\n"):
                    if re.search(GPG_GOOD_SIGNATURE_USERNAME, line) is not None:
                        dprint("Signature #%d is good." % (index + 1))
                        good_signature = True
                        continue #valid signature
                if not good_signature:
                    dprint("Signature #%d is bad." % (index + 1))
                    return False
    return True

def verify_signature_trusted(sha256_string, signature,
                             trusted_keyring_filename):
    """Verifies that the signatures are valid and are trusted.

    A PGP signature is trusted in this context if it was created using a private
    key that corresponds to a trusted public key.

    Args:
        sha256_string (str): The properly formatted list of SHA256 hashes of
            files that has been signed, allegedly.
        signatures (str): A PGP messages representing a signature by an
            allegedly trusted partiy of `sha256_string`.
        trusted_keyring_filename (str): The filename of the keyring of trusted
            keys generated by GPG.

    Returns:
        [`None`, `None`] if the signature does not match the string, or does not
        correspond to a trusted public key; a pair of strings
        [username, long_id] if it does correspond to a trusted public key.
    """
    username = None
    long_id = None

    with NamedTemporaryFile() as sha256_tmp_file:
        sha256_tmp_file.write(sha256_string)
        sha256_tmp_file.flush()
        target_filename = sha256_tmp_file.name

        with NamedTemporaryFile() as sig_tmp_file:
            sig_tmp_file.write(signature)
            sig_tmp_file.flush()
            signature_filename = sig_tmp_file.name

            cmd = build_verify_trust_command(
                trusted_keyring_filename, signature_filename, target_filename)

            stdout = run_command(cmd)
            for line in stdout.split("\n"):
                match1 = re.match(GPG_GOOD_SIGNATURE_USERNAME, line)
                if match1 is not None:
                    username = match1.group(1)
                else:
                    match2 = re.match(GPG_GOOD_SIGNATURE_LONG_KEY, line)
                    if match2 is not None:
                        long_id = match2.group(1)

    if username is None or long_id is None:
        return [None, None]
    else:
        return [username, long_id]

def get_num_unique_trusted_sigs(sha256_string, signatures, trusted_keyring_filename):
    """Returns the number unique trusted public keys used to sign the string.

    Multiple signatures from either the same username or 64-bit key ID do not
    count as unique.

    Returns: int: Number of unique trusted signatures.
    """
    unique_users = set() #ignores duplicates
    unique_long_ids = set() #ignores duplicates
    for signature in signatures:
        username, long_id = verify_signature_trusted(sha256_string, signature,
                                                     trusted_keyring_filename)
        if username is not None:
            unique_users.add(username)
        if long_id is not None:
            unique_long_ids.add(long_id)

    return min(len(unique_users), len(unique_long_ids))


def dprint(data):
    """Print debug data."""
    if ENABLE_DEBUG_PRINT:
        print "DEBUG: %s" % str(data)


def _main():
    print "DEBUG MODE for common.py"
    #print get_string_sig("asdf", "demo1@example.com")

if __name__ == '__main__':
    _main()
