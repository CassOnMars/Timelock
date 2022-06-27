# Timelock

    timelock - simple timelock-based encryption tool
        timelock encrypt <input filename> <output filename>
            encrypts a file, asks for public variables via STDIN, produces all public variables to distribute to STDOUT.
        timelock decrypt <input filename> <output filename>
            decrypts a file, asks for public variables via STDIN.

Uses the RSA-style timelock puzzle to make a ciphertext decryptable, but only after a configured amount of time has passed. See https://people.csail.mit.edu/rivest/pubs/RSW96.pdf for more details.

## Encrypt/Decrypt Inputs:

A: A value which will be hashed to serve as the `a` value.
T: The `t` parameter, or number of squarings.

## Encrypt Outputs/Decrypt Inputs:

Modulus: The `n` value.
CK: The encrypted value of the decryption key `K`, `C_K = K + a^(2^t) (mod n)`

