# vim: set et ai ts=4 sts=4 sw=4:
from __future__ import print_function
import os
import textwrap
import base64
import struct
import ctypes
import javaobj
import tempfile

from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc5208, rfc2459
from pyasn1.type import univ
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
class IllegalPasswordCharactersException(KeystoreException):
    """Signifies that the given password contains illegal characters for the given store."""
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
    # Note: as of PyAsn1 0.2.1+, BitString objects have a .asOctets() method that you can call directly to do this,
    # but that version is fairly recent at the time of writing (few months old). So to ease the lives of people stuck
    # on older versions, we'll stick with this for now.
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

class cd(object):
    def __init__(self, newpath):
        self.newpath = os.path.expanduser(newpath)
    def __enter__(self):
        self.oldpath = os.getcwd()
        os.chdir(self.newpath)
    def __exit__(self, etype, value, traceback):
        os.chdir(self.oldpath)

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

def pkcs8_unwrap(pkcs8_key):
    """
    Given a PKCS#8-encoded private key, returns the algorithm OID and raw key contained within it.
    """
    try:
        private_key_info = asn1_checked_decode(pkcs8_key, rfc5208.PrivateKeyInfo())
        algorithm_oid = private_key_info['privateKeyAlgorithm']['algorithm'].asTuple()
        key           = private_key_info['privateKey'].asOctets()
        return (key, algorithm_oid)
    except PyAsn1Error as e:
        raise BadKeyEncodingException("Failed to parse provided key as a PKCS#8 PrivateKeyInfo structure", e)

def pkcs8_wrap(key, algorithm_oid, algorithm_params=None):
    """
    Given an algorithm OID tuple and a raw key, returns a PKCS#8-encoded private key.
    """
    algorithm_params = algorithm_params or univ.Null()

    private_key_info = rfc5208.PrivateKeyInfo()
    private_key_info.setComponentByName('version','v1')
    a = rfc2459.AlgorithmIdentifier()
    a.setComponentByName('algorithm', algorithm_oid)
    a.setComponentByName('parameters', algorithm_params)
    private_key_info.setComponentByName('privateKeyAlgorithm', a)
    private_key_info.setComponentByName('privateKey', key)

    return encoder.encode(private_key_info)

class tempfile_path(object):
    """
    Upon entering a with-context, creates and returns the path to an unopened temporary file on disk. Upon exiting, the temporary file is removed.
    Alternative for tempfile.NamedTemporaryFile() to work around the following phrase in its documentation:
        Whether the name can be used to open the file a second time, while the named temporary file is still open, varies across platforms
        (it can be so used on Unix; it cannot on Windows NT or later).
    """
    def __init__(self):
        self.fd, self.path = tempfile.mkstemp()
    def __enter__(self):
        return self.path
    def __exit__(self, etype, value, traceback):
        os.remove(self.path)

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

def decode_modified_utf8(xbytes):
    # Java's modified UTF-8 = CESU-8, except:
    #   U+0000 is encoded in its overlong 2-byte sequence 0xC080 instead of single-byte 0x00.
    return decode_cesu8(xbytes.replace(b"\xc0\x80", b"\x00"))

def decode_cesu8(xbytes):
    # CESU-8 = UTF-8, except:
    #   supplementary characters (i.e. in the U+10000 to U+10FFFF range) are encoded by taking their UTF-16 representation as a pair of surrogate code points,
    #   and encoding each one of those individually as though they were separate characters (they're not, they're surrogates; their code points are unassigned).
    #   UTF-8 encodes code points in the range U+0800 to U+FFFF with 3 bytes, and there are 2 such surrogates, so that makes 6 bytes per supplementary character.
    #
    # The CESU-8 spec is surprisingly no-nonsense and concise, give it a read:
    #   http://www.unicode.org/reports/tr26/
    #
    # So to implement this, there's a few things to consider:
    #   - We want a strict encoder/decoder, because we need perfect interoperability with Java's modified UTF-8.
    #
    #   - A CESU-8/MUTF-8 decoder already exists in the ftfy.bad_codecs module, but it is explicitly designed to be non-validating and will accept input that Java rejects
    #     (specifically, regular UTF-8 4-byte sequences).
    #
    #   - As of Python 3.1 there is a 'surrogatepass' error handler for the utf-8 decoder that can be used to let UTF-16 surrogate code points pass through (rather than
    #     complain that those code points are unassigned) and handle them separately afterwards.
    #     https://bugs.python.org/issue2857 has a good example of how it can be used.
    #
    #   - Python versions < 3.3 can come in wide or narrow builds; in the latter case, characters > U+FFFF cannot be represented as a single character in strings,
    #     causing some subtle issues when writing algorithms that need to deal with them.
    #
    # So rather than deal with all possible combinations of quirks across Python versions, here's a manual, bit-twiddling, strict CESU-8 decoder that should
    # work across any Python version/build. I'm sure it's super slow, but for our case our expected inputs are few and short, and we care much more about not
    # corrupting keystores.

    xbytes = bytearray(xbytes) # make xbytes[i] return int instead of str in Python 2.x (can't bit-shift strings)

    # we expect our inputs to be short and to rarely contain any 'fancy' characters; it's likely we can skip any custom processing altogether
    if all(b <= 0x7F for b in xbytes):
        return xbytes.decode("ascii")

    utf16 = bytearray()

    BB = struct.Struct('BB')
    L = len(xbytes)
    i = 0
    while i < L:
        b = xbytes[i]
        if b <= 0x7F:
            # 0xxx.xxxx
            utf16 += b2.pack(b)
            i += 1
        elif (b >> 4) in [0xC, 0xD]:
            # 2-continuation: 110x.xxxx 10xx.xxxx
            if not i + 1 < L:
                raise ValueError("Invalid CESU-8: truncated character")
            byte2 = xbytes[i+1]
            if (byte2 & 0xC0) != 0x80:
                raise ValueError("Invalid CESU-8: invalid continuation")
            codepoint = ((b & 0x1F) << 6) | (byte2 & 0x3F)
            if codepoint < 0x80: # reject overlong sequences
                raise ValueError("Invalid CESU-8: overlong sequences not allowed")
            utf16 += b2.pack(codepoint)
            i += 2
        elif (b >> 4) == 0xE:
            # 3-continuation: 1110.xxxx 10xx.xxxx 10xx.xxxx
            if not i + 2 < L:
                raise ValueError("Invalid CESU-8: truncated character")
            byte2 = xbytes[i+1]
            byte3 = xbytes[i+2]
            if not ((byte2 & 0xC0) == 0x80 and (byte3 & 0xC0) == 0x80):
                raise ValueError("Invalid CESU-8: invalid continuation")
            codepoint = ((b & 0x0F) << 12) | ((byte2 & 0x3F) << 6) | ((byte3 & 0x3F) << 0)
            if codepoint < 0x800: # reject overlong sequences
                raise ValueError("Invalid CESU-8: overlong sequences not allowed")
            utf16 += b2.pack(codepoint)
            i += 3
        else:
            # either a 4-continuation or a bad leader byte
            raise ValueError("Invalid CESU-8")

    return utf16.decode("utf-16be", "strict")

def encode_modified_utf8(xstr):
    return encode_cesu8(xstr).replace(b"\x00", b"\xc0\x80")

def encode_cesu8(xstr):
    BB = struct.Struct('BB')
    BBB = struct.Struct('BBB')
    result = bytearray()

    utf16 = xstr.encode("utf-16be")
    assert len(utf16) % 2 == 0

    for i in range(0, len(utf16), 2):
        code_unit = b2.unpack_from(utf16[i:i+2])[0]
        if code_unit <= 0x007F:
            result += b1.pack(code_unit)
        elif code_unit > 0x07FF:
            # this code unit is either a single character or part of a pair of surrogate code points;
            # CESU-8 doesn't care about the difference and encodes either as a UTF-8 3-byte continuation
            utf8_b1 = 0xE0 | ((code_unit >> 12) & 0x0F)
            utf8_b2 = 0x80 | ((code_unit >> 6)  & 0x3F)
            utf8_b3 = 0x80 | ((code_unit >> 0)  & 0x3F)
            result += BBB.pack(utf8_b1, utf8_b2, utf8_b3)
        else: # regular 2-byte continuation
            utf8_b1 = 0xC0 | ((code_unit >> 6)  & 0x1F)
            utf8_b2 = 0x80 | ((code_unit >> 0)  & 0x3F)
            result += BB.pack(utf8_b1, utf8_b2)

    return bytes(result)

