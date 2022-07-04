from random import randint
from hashlib import sha256
from sys import byteorder


MAX_NUMBER_256 = 2 ** 256 - 1


def key_gen():
    """
    Key generation:
    • Private key: Two pairs of 256 numbers of 256 bits each.
    • Public key: Hash each of the 512 numbers of the private key.
    """

    # Initialize private and public keys with empty lists
    private_key = {
        's1': [],
        's2': []
    }
    public_key = []

    # Generate private key pairs
    for i in range(256):
        private_key['s1'].append(randint(0, MAX_NUMBER_256))
        private_key['s2'].append(randint(0, MAX_NUMBER_256))

    # Compute Public key based on SHA256
    for number in private_key['s1'] + private_key['s2']:
        hash = sha256(number.to_bytes(32, byteorder))
        # Convert the hash digest from base 16 to int
        public_key.append(int(hash.hexdigest(), 16))

    return private_key, public_key


def sign_message(message, private_key):
    """
    • Hash a message using SHA-256.
    • For each bit of the message hash pick the corresponding number from the pair
    of numbers of the private key, if 0 use first pair, if 1 use second pair.
    """
    sha256_hash = sha256(message.encode('utf-8'))
    sha256_hash_string = format(int(sha256_hash.hexdigest(), 16), 'b')

    # Add padding with '0's to have 256 bits in length
    sha256_hash_string = '0' * (256 - len(sha256_hash_string)) + sha256_hash_string
    lamport_signature = []

    for index in range(256):

        if sha256_hash_string[index] == '0':
            lamport_signature.append(private_key['s1'][index])

        else:
            lamport_signature.append(private_key['s2'][index])

    return lamport_signature


def verify_signature(message, lamport_signature, public_key):
    """
    • Hash a message using SHA-256.
    • For each bit of the message hash pick the corresponding number from the numbers
    of the public key, if 0 use index, if 1 use index + 256 (since we have a list of 512 number)
    • Hash each number of the received signature .
    • Compare the two sequences.
    • Return True if the sequences match, otherwise return False.
    """
    sha256_hash = sha256(message.encode('utf-8'))
    sha256_hash_string = format(int(sha256_hash.hexdigest(), 16), 'b')
    # Add padding with '0's to have 256 bits in length
    sha256_hash_string = '0' * (256 - len(sha256_hash_string)) + sha256_hash_string
    lamport_hash = []

    for index in range(256):
        if sha256_hash_string[index] == '0':
            lamport_hash.append(public_key[index])
        else:
            lamport_hash.append(public_key[index + 256])

    for index in range(256):
        hash = sha256(lamport_signature[index].to_bytes(32, byteorder))
        if int(hash.hexdigest(), 16) != lamport_hash[index]:
            return False
    
    return True


if __name__ == '__main__':
    s1, p1 = key_gen() # legit keys pair
    s2, p2 = key_gen() # other keys pair
    message = 'Hello blockchain!'

    print("Siging message with s1..")
    legit_signature = sign_message(message, s1)
    print("Verifiying signature with p1..")
    if verify_signature(message, legit_signature, p1):
        print('==> Message verified!')
    else:
        print('==> Wrong signature!')

    print("Siging message with s2..")
    other_signature = sign_message(message, s2)
    print("Verifiying signature with p1..")
    if verify_signature(message, other_signature, p1):
        print('==> Message verified!')
    else:
        print('==> Wrong signature!')

"""
Output:
Siging message with s1..
Verifiying signature with p1..
==> Message verified!
Siging message with s2..
Verifiying signature with p1..
==> Wrong signature!
"""