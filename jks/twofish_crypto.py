# vim: set et ai ts=4 sts=4 sw=4:
from __future__ import absolute_import, print_function
from cryptography import utils
from cryptography.hazmat.primitives.ciphers import BlockCipherAlgorithm, CipherAlgorithm, CipherContext, modes
from cryptography.hazmat.backends.interfaces import CipherBackend

import twofish
from jks.util import xor_bytearrays, BadDataLengthException

def _verify_key_size(algorithm, key):
    # Verify that the key size matches the expected key size
    if len(key) * 8 not in algorithm.key_sizes:
        raise ValueError("Invalid key size ({0}) for {1}.".format(
            len(key) * 8, algorithm.name
        ))
    return key

@utils.register_interface(BlockCipherAlgorithm)
@utils.register_interface(CipherAlgorithm)
class TwofishAlgorithm(object):
    name = "Twofish"
    block_size = 128
    key_sizes = frozenset([128, 192, 256])

    def __init__(self, key):
        self.key = _verify_key_size(self, key)

    @property
    def key_size(self):
        return len(self.key)*8

@utils.register_interface(CipherContext)
class TwofishCBCContext(object):
    def __init__(self, backend, cipher, mode, operation):
        if operation not in [1,2]:
            return ValueError("Invalid operation: %s" % repr(operation))
        assert isinstance(mode, modes.CBC)
        assert isinstance(cipher, TwofishAlgorithm)
        self._backend = backend
        self._operation = operation
        self._twofish = twofish.Twofish(cipher.key)
        self._buffer = bytearray()
        self._last_cipher_block = bytearray(mode.initialization_vector)

    def update(self, data):
        # fill up the buffer, then consume as many whole blocks as are available
        result = bytearray()
        self._buffer.extend(data)

        if self._operation == 1: # encrypt
            for i in range(0, len(self._buffer)//16*16, 16):
                plaintext_block = self._buffer[i:i+16]
                cipher_block = self._twofish.encrypt(bytes(xor_bytearrays(plaintext_block, self._last_cipher_block)))
                result.extend(cipher_block)
                self._last_cipher_block = bytearray(cipher_block)

        else: # decrypt
            for i in range(0, len(self._buffer)//16*16, 16):
                cipher_block = self._buffer[i:i+16]
                plaintext_block = xor_bytearrays(bytearray(self._twofish.decrypt(bytes(cipher_block))), self._last_cipher_block)
                result.extend(plaintext_block)
                self._last_cipher_block = cipher_block

        # drop all consumed blocks
        del self._buffer[0:(len(self._buffer)//16*16)]
        assert len(result)%16 == 0
        return bytes(result)


    def finalize(self):
        # remaining buffer size must be a multiple of the block size
        result = b""
        if len(self._buffer) > 0:
            if len(self._buffer) % 16 != 0:
                raise BadDataLengthException("Insufficient ciphertext length: must be a multiple of 16")
            result = self.update(b"")

        self._buffer = None
        self._twofish = None
        self._last_cipher_block = None
        self._operation = None
        return result

@utils.register_interface(CipherBackend)
class TwofishCBCBackend(object):
    _ENCRYPT = 1
    _DECRYPT = 2
    def cipher_supported(self, cipher, mode):
        if isinstance(cipher, TwofishAlgorithm) and isinstance(mode, modes.CBC):
            return True
        else:
            return False

    def create_symmetric_encryption_ctx(self, cipher, mode):
        return TwofishCBCContext(self, cipher, mode, self._ENCRYPT)
    def create_symmetric_decryption_ctx(self, cipher, mode):
        return TwofishCBCContext(self, cipher, mode, self._DECRYPT)
