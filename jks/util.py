# vim: set et ai ts=4 sts=4 sw=4:
from __future__ import print_function
import textwrap
import base64
import struct
import ctypes
import javaobj

from pyasn1.codec.ber import decoder
from pyasn1.error import PyAsn1Error

b8 = struct.Struct('>Q')
b4 = struct.Struct('>L') # unsigned
b2 = struct.Struct('>H')
b1 = struct.Struct('B') # unsigned

py23basestring = ("".__class__, u"".__class__) # useful for isinstance checks

RSA_ENCRYPTION_OID = (1,2,840,113549,1,1,1)
DSA_OID            = (1,2,840,10040,4,1)       # identifier for DSA public/private keys; see RFC 3279, section 2.2.2 (e.g. in PKCS#8 PrivateKeyInfo or X.509 SubjectPublicKeyInfo)
DSA_WITH_SHA1_OID  = (1,2,840,10040,4,3)       # identifier for the DSA signature algorithm; see RFC 3279, section 2.3.2 (e.g. in X.509 signatures)

class KeystoreException(Exception):
    """Superclass for all pyjks exceptions."""
    pass
class KeystoreSignatureException(KeystoreException):
    """Signifies that the supplied password for a keystore integrity check is incorrect."""
    pass
class DuplicateAliasException(KeystoreException):
    """Signifies that duplicate aliases were encountered in a keystore."""
    pass
class NotYetDecryptedException(KeystoreException):
    """
    Signifies that an attribute of a key store entry can not be accessed because the entry has not yet been decrypted.

    By default, the keystore ``load`` and ``loads`` methods automatically try to decrypt all key entries using the store password.
    Any keys for which that attempt fails are returned undecrypted, and will raise this exception when its attributes are accessed.

    To resolve, first call decrypt() with the correct password on the entry object whose attributes you want to access.
    """
    pass
class BadKeystoreFormatException(KeystoreException):
    """Signifies that a structural error was encountered during key store parsing."""
    pass
class BadDataLengthException(KeystoreException):
    """Signifies that given input data was of wrong or unexpected length."""
    pass
class BadPaddingException(KeystoreException):
    """Signifies that bad padding was encountered during decryption."""
    pass
class BadHashCheckException(KeystoreException):
    """Signifies that a hash computation did not match an expected value."""
    pass
class BadKeyEncodingException(KeystoreException):
    """Signifies that a key that was declared to be encoded in a particular format could not be interpreted as such"""
    pass
class DecryptionFailureException(KeystoreException):
    """Signifies failure to decrypt a value."""
    pass
class UnsupportedKeystoreVersionException(KeystoreException):
    """Signifies an unexpected or unsupported keystore format version."""
    pass
class UnexpectedJavaTypeException(KeystoreException):
    """Signifies that a serialized Java object of unexpected type was encountered."""
    pass
class UnexpectedAlgorithmException(KeystoreException):
    """Signifies that an unexpected cryptographic algorithm was used in a keystore."""
    pass
class UnexpectedKeyEncodingException(KeystoreException):
    """Signifies that a key was stored in an unexpected format or encoding."""
    pass
class UnsupportedKeystoreTypeException(KeystoreException):
    """Signifies that the keystore was an unsupported type."""
    pass
class UnsupportedKeystoreEntryTypeException(KeystoreException):
    """Signifies that the keystore entry was an unsupported type."""
    pass
class UnsupportedKeyFormatException(KeystoreException):
    """Signifies that the key format was an unsupported type."""
    pass

def as_hex(ba):
    return "".join(r"{0:02x}".format(b) for b in bytearray(ba))

def as_pem(der_bytes, type):
    result = "-----BEGIN %s-----\n" % type
    result += "\n".join(textwrap.wrap(base64.b64encode(der_bytes).decode('ascii'), 64))
    result += "\n-----END %s-----" % type
    return result

def bitstring_to_bytes(bitstr):
    """
    Converts a pyasn1 univ.BitString instance to byte sequence of type 'bytes'.
    The bit string is interpreted big-endian and is left-padded with 0 bits to form a multiple of 8.
    """
    bitlist = list(bitstr)
    bits_missing = (8 - len(bitlist) % 8) % 8
    bitlist = [0]*bits_missing + bitlist # pad with 0 bits to a multiple of 8
    result = bytearray()
    for i in range(0, len(bitlist), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bitlist[i+j]
        result.append(byte)
    return bytes(result)

def xor_bytearrays(a, b):
    return bytearray([x^y for x,y in zip(a,b)])

def print_pem(der_bytes, type):
    print(as_pem(der_bytes, type))

def pkey_as_pem(pk):
    if pk.algorithm_oid == RSA_ENCRYPTION_OID:
        return as_pem(pk.pkey, "RSA PRIVATE KEY")
    else:
        return as_pem(pk.pkey_pkcs8, "PRIVATE KEY")

def xxd_char(byte):
    return chr(byte) if (byte >= 32 and byte < 127) else "."

def xxd(bytez, bytes_per_row=16, bytes_per_group=2):
    """
    Generates a binary dump of the given data in (roughly) the same format as the Linux xxd utility.
    """
    result = ""
    total = len(bytez)
    for row_offset in range(0, total, bytes_per_row):
        hexparts = []
        asciipart = ""
        for group_offset in range(0, bytes_per_row, bytes_per_group):
            hexpart = ""
            for byte_offset in range(0, bytes_per_group):
                offset = row_offset + group_offset + byte_offset
                if offset < total:
                    hexpart += "%02x" % (bytez[offset],)
                    asciipart += "%1s" % xxd_char(bytez[offset])
                else:
                    hexpart += "  "
                    asciipart += " "
            hexparts.append(hexpart)
        result += "%07x: %s  %s\n" % (row_offset, " ".join(hexparts), asciipart)
    return result

def asn1_checked_decode(asn1_bytes, asn1Spec):
    """
    Decodes the input ASN.1 byte sequence and returns it as an object of the given spec if it could be successfully decoded as such,
    or raises a PyAsn1Error otherwise.
    """
    obj = decoder.decode(asn1_bytes, asn1Spec=asn1Spec)[0]
    # Note: despite the asn1Spec parameter to decoder.decode, you can still get an object of a different type, on which the remainder of the operations
    # you might want to do on those (like accessing members) raises a TypeError.
    # Motivating use case is feeding b"\x00\x00" to decoder.decode(); regardless of asn1Spec, you'll get an EndOfOctets() object that will throw TypeErrors
    # when you try to access members through obj['foo'] syntax.
    if not isinstance(obj, asn1Spec.__class__): # old pyasn1 versions still use old-style classes
        raise PyAsn1Error("Not a valid %s structure" % (asn1Spec.__class__.__name__, ))
    return obj

def strip_pkcs5_padding(m):
    """
    Drop PKCS5 padding:  8-(||M|| mod 8) octets each with value 8-(||M|| mod 8)
    Note: ideally we would use pycrypto for this, but it doesn't provide padding functionality and the project is virtually dead at this point.
    """
    return strip_pkcs7_padding(m, 8)

def strip_pkcs7_padding(m, block_size):
    """
    Same as PKCS#5 padding, except generalized to block sizes other than 8.
    """
    if len(m) < block_size or len(m) % block_size != 0:
        raise BadPaddingException("Unable to strip padding: invalid message length")

    m = bytearray(m) # py2/3 compatibility: always returns individual indexed elements as ints
    last_byte = m[-1]
    # the <last_byte> bytes of m must all have value <last_byte>, otherwise something's wrong
    if (last_byte <= 0 or last_byte > block_size) or (m[-last_byte:] != bytearray([last_byte])*last_byte):
        raise BadPaddingException("Unable to strip padding: invalid padding found")

    return bytes(m[:-last_byte]) # back to 'str'/'bytes'

def add_pkcs7_padding(m, block_size):
    if block_size <= 0 or block_size > 255:
        raise ValueError("Invalid block size")

    m = bytearray(m)
    num_padding_bytes = block_size - (len(m) % block_size)
    m = m + bytearray([num_padding_bytes]*num_padding_bytes)
    return bytes(m)

def java_is_subclass(obj, class_name):
    """Given a deserialized JavaObject as returned by the javaobj library,
    determine whether it's a subclass of the given class name.
    """
    clazz = obj.get_class()
    while clazz:
        if clazz.name == class_name:
            return True
        clazz = clazz.superclass
    return False

def java2bytes(java_byte_list):
    """Convert the value returned by javaobj for a byte[] to a byte
    string (i.e. a 'bytes' instance):
      - Prior to version 0.2.3, javaobj returns Java byte arrays
        as a list of Python integers in the range [-128, 127].
      - As of 0.2.3+, javaobj returns a bytes instance.

    In case of a <0.2.3 integer list, reinterpret each integer as
    an unsigned byte, take its new value as another Python int
    (now remapped to the range [0, 255]), and use struct.pack() to
    create the matching byte string.
    """
    if isinstance(java_byte_list, bytes):
        return java_byte_list
    args = [ctypes.c_ubyte(sb).value for sb in java_byte_list]
    return struct.pack("%dB" % len(java_byte_list), *args)

_classdesc_ByteArray = None
def bytes2java(bytez):
    """
    Converts a Python 'bytes' object to javaobj's representation of a byte[]
    """
    global _classdesc_ByteArray
    if not _classdesc_ByteArray:
        _classdesc_ByteArray = javaobj.JavaClass()
        _classdesc_ByteArray.name = "[B"
        _classdesc_ByteArray.serialVersionUID = -5984413125824719648
        _classdesc_ByteArray.flags = javaobj.JavaObjectConstants.SC_SERIALIZABLE

    data = [ctypes.c_byte(b).value for b in bytearray(bytez)] # convert a Python bytes/bytearray instance to an array of signed integers

    array_obj = javaobj.JavaArray()
    array_obj.classdesc = _classdesc_ByteArray
    array_obj.extend(data)

    return array_obj

