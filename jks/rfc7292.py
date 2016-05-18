# vim: set ai et ts=4 sts=4 sw=4:
from __future__ import print_function
import hashlib
import ctypes
from pyasn1.type import univ, namedtype
from cryptography import utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import kdf, constant_time
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from .util import xor_bytearrays, add_pkcs7_padding, strip_pkcs7_padding, BadDataLengthException, py23basestring, as_hex
from .twofish_crypto import TwofishCBCBackend, TwofishCBCContext, TwofishAlgorithm

PBE_WITH_SHA1_AND_TRIPLE_DES_CBC_OID = (1,2,840,113549,1,12,1,3)

class Pkcs12PBEParams(univ.Sequence):
    """Virtually identical to PKCS#5's PBEParameter, but nevertheless has its own definition in its own RFC, so gets its own class."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('salt', univ.OctetString()),
        namedtype.NamedType('iterations', univ.Integer())
    )

@utils.register_interface(kdf.KeyDerivationFunction)
class PKCS12KDF(object):
    """
    Implements PKCS#12 key derivation as specified in RFC 7292, Appendix B, "Deriving Keys and IVs from Passwords and Salt".
    Ported from BC's implementation in org.bouncycastle.crypto.generators.PKCS12ParametersGenerator.
    """
    PURPOSE_KEY_MATERIAL = 1
    PURPOSE_IV_MATERIAL  = 2
    PURPOSE_MAC_MATERIAL = 3

    def __init__(self, hashfn, salt, iteration_count, purpose_byte, desired_size):
        """
        hashfn:            hash function to use (expected to support the hashlib interface and attributes)
        salt:              byte sequence
        purpose:           "purpose byte", signifies the purpose of the generated pseudorandom key material
        desired_key_size:  desired amount of bytes of key material to generate
        """
        self.salt = salt
        self.hashfn = hashfn
        self.iteration_count = iteration_count
        self.purpose_byte = purpose_byte
        self.desired_size = desired_size

    def derive(self, key_material):
        """
        key_material:      password string (not yet transformed into bytes)
        """
        if not isinstance(key_material, py23basestring):
            raise ValueError("Password must be a string, not a byte sequence")

        password_bytes = (key_material.encode("utf-16be") + b"\x00\x00") if len(key_material) > 0 else b""
        u = self.hashfn().digest_size # in bytes
        v = self.hashfn().block_size  # in bytes

        _salt = bytearray(self.salt)
        _password_bytes = bytearray(password_bytes)

        D = bytearray([self.purpose_byte])*v
        S_len = ((len(_salt) + v -1)//v)*v
        S = bytearray([_salt[n % len(_salt)] for n in range(S_len)])
        P_len = ((len(_password_bytes) + v -1)//v)*v
        P = bytearray([_password_bytes[n % len(_password_bytes)] for n in range(P_len)])

        I = S + P
        c = (self.desired_size + u - 1)//u
        derived_key = bytearray()

        for i in range(1,c+1):
            A = self.hashfn(bytes(D + I)).digest()
            for j in range(self.iteration_count - 1):
                A = self.hashfn(A).digest()

            A = bytearray(A)
            B = bytearray([A[n % len(A)] for n in range(v)])

            # Treating I as a concatenation I_0, I_1, ..., I_(k-1) of v-bit
            # blocks, where k=ceiling(s/v)+ceiling(p/v), modify I by
            # setting I_j=(I_j+B+1) mod 2^v for each j.
            for j in range(len(I)//v):
                self._adjust(I, j*v, B)

            derived_key.extend(A)

        # truncate derived_key to the desired size
        derived_key = derived_key[:self.desired_size]
        return bytes(derived_key)

    def _adjust(self, a, a_offset, b):
        """
        a = bytearray
        a_offset = int
        b = bytearray
        """
        x = (b[-1] & 0xFF) + (a[a_offset + len(b) - 1] & 0xFF) + 1
        a[a_offset + len(b) - 1] = ctypes.c_ubyte(x).value
        x >>= 8

        for i in range(len(b)-2, -1, -1):
            x += (b[i] & 0xFF) + (a[a_offset + i] & 0xFF)
            a[a_offset + i] = ctypes.c_ubyte(x).value
            x >>= 8

    def verify(self, key_material, expected_key):
        derived_key = self.derive(key_material)
        if not constant_time.bytes_eq(derived_key, expected_key):
            raise InvalidKey("Keys do not match.")

def derive_key(hashfn, purpose_byte, password_str, salt, iteration_count, desired_key_size):
    kdf = PKCS12KDF(hashfn, salt, iteration_count, purpose_byte, desired_key_size)
    return kdf.derive(password_str)

def decrypt_PBEWithSHAAnd3KeyTripleDESCBC(data, password_str, salt, iteration_count):
    if len(data) % 8 != 0:
        raise BadDataLengthException("encrypted data length is not a multiple of 8")

    iv  = derive_key(hashlib.sha1, PKCS12KDF.PURPOSE_IV_MATERIAL,  password_str, salt, iteration_count, 64//8)
    key = derive_key(hashlib.sha1, PKCS12KDF.PURPOSE_KEY_MATERIAL, password_str, salt, iteration_count, 192//8)

    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    padded_plaintext = cipher.update(data) + cipher.finalize()

    result = strip_pkcs7_padding(padded_plaintext, 8)
    return result

def encrypt_PBEWithSHAAndTwofishCBC(plaintext_data, password, salt, iteration_count):
    """
    Encrypts a value with PBEWithSHAAndTwofishCBC, assuming PKCS#12-generated PBE parameters.
    (Not explicitly defined as an algorithm in RFC 7292, but defined here nevertheless because of the assumption of PKCS#12 parameters).
    """
    plaintext_data = add_pkcs7_padding(plaintext_data, 16)

    iv  = derive_key(hashlib.sha1, PKCS12KDF.PURPOSE_IV_MATERIAL,  password, salt, iteration_count, 16)
    key = derive_key(hashlib.sha1, PKCS12KDF.PURPOSE_KEY_MATERIAL, password, salt, iteration_count, 256//8)
    cipher = Cipher(TwofishAlgorithm(key), modes.CBC(iv), backend=TwofishCBCBackend()).encryptor()

    result = cipher.update(plaintext_data) + cipher.finalize()
    return result

def decrypt_PBEWithSHAAndTwofishCBC(encrypted_data, password, salt, iteration_count):
    """
    Decrypts PBEWithSHAAndTwofishCBC, assuming PKCS#12-generated PBE parameters.
    (Not explicitly defined as an algorithm in RFC 7292, but defined here nevertheless because of the assumption of PKCS#12 parameters).
    """
    if len(encrypted_data) % 16 != 0:
        raise BadDataLengthException("encrypted data length is not a multiple of 16")

    iv  = derive_key(hashlib.sha1, PKCS12KDF.PURPOSE_IV_MATERIAL,  password, salt, iteration_count, 16)
    key = derive_key(hashlib.sha1, PKCS12KDF.PURPOSE_KEY_MATERIAL, password, salt, iteration_count, 256//8)

    cipher = Cipher(TwofishAlgorithm(key), modes.CBC(iv), backend=TwofishCBCBackend()).decryptor()
    padded_plaintext = cipher.update(encrypted_data) + cipher.finalize()

    result = strip_pkcs7_padding(padded_plaintext, 16)
    return result

