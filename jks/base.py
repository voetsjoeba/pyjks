# vim: set et ai ts=4 sts=4 sw=4:
from pyasn1.codec.ber import encoder, decoder
from pyasn1_modules import rfc5208, rfc2459
from pyasn1.type import univ
from .util import *

# basic value types that can be entered into keystores through respective entries

class TrustedCertificate(object):
    def __init__(self, type, cert):
        if not isinstance(type, py23basestring):
            raise Exception("Bad data type") # TODO
        if not isinstance(cert, bytes):
            raise Exception("Bad data type") # TODO
        self.type = type
        self.cert = cert

class PublicKey(object):
    def __init__(self, key_info):
        spki = decoder.decode(key_info, asn1Spec=rfc2459.SubjectPublicKeyInfo())[0]
        self.key_info = key_info
        self.key = bitstring_to_bytes(spki['subjectPublicKey'])
        self.algorithm_oid = spki['algorithm']['algorithm'].asTuple()

class PrivateKey(object):
    def __init__(self, key, certs, key_format='pkcs8'):
        self.certs = certs
        self.key = None
        self.key_pkcs8 = None
        self.algorithm_oid = None

        if not all(isinstance(c, TrustedCertificate) for c in self.certs):
            raise ValueError("certs argument must be a list of TrustedCertificate instances")

        if key_format == 'pkcs8':
            private_key_info = decoder.decode(key, asn1Spec=rfc5208.PrivateKeyInfo())[0]

            self.algorithm_oid = private_key_info['privateKeyAlgorithm']['algorithm'].asTuple()
            self.key = private_key_info['privateKey'].asOctets()
            self.key_pkcs8 = key

        elif key_format == 'rsa_raw':
            self.algorithm_oid = RSA_ENCRYPTION_OID

            # We must encode it to pkcs8
            private_key_info = rfc5208.PrivateKeyInfo()
            private_key_info.setComponentByName('version','v1')
            a = rfc2459.AlgorithmIdentifier()
            a.setComponentByName('algorithm', self.algorithm_oid)
            a.setComponentByName('parameters', univ.Null())
            private_key_info.setComponentByName('privateKeyAlgorithm', a)
            private_key_info.setComponentByName('privateKey', key)

            self.key_pkcs8 = encoder.encode(private_key_info)
            self.key = key

        else:
            raise UnsupportedKeyFormatException("Key Format '%s' is not supported" % key_format)

class SecretKey(object):
    def __init__(self, key, algorithm):
        self.key = key
        self.key_size = len(self.key)*8
        self.algorithm = algorithm

class AbstractKeystore(object):
    """
    Abstract superclass for keystores.
    """
    def __init__(self, store_type, entries):
        self.store_type = store_type  #: A string indicating the type of keystore that was loaded.
        self.entries = dict(entries)  #: A dictionary of all entries in the keystore, mapped by alias.

    @classmethod
    def load(cls, filename, store_password, try_decrypt_keys=True):
        """
        Convenience wrapper function; reads the contents of the given file
        and passes it through to :func:`loads`. See :func:`loads`.
        """
        with open(filename, 'rb') as file:
            input_bytes = file.read()
            ret = cls.loads(input_bytes,
                            store_password,
                            try_decrypt_keys=try_decrypt_keys)
        return ret

    def save(self, filename, store_password):
        """
        Convenience wrapper function; calls the :func:`saves`
        and saves the content to a file.
        """
        with open(filename, 'wb') as file:
            keystore_bytes = self.saves(store_password)
            file.write(keystore_bytes)

    @classmethod
    def _read_utf(cls, data, pos, kind=None):
        """
        :param kind: Optional; a human-friendly identifier for the kind of UTF-8 data we're loading (e.g. is it a keystore alias? an algorithm identifier? something else?).
                     Used to construct more informative exception messages when a decoding error occurs.
        """
        size = b2.unpack_from(data, pos)[0]
        pos += 2
        try:
            return data[pos:pos+size].decode('utf-8'), pos+size
        except (UnicodeEncodeError, UnicodeDecodeError) as e:
            raise BadKeystoreFormatException(("Failed to read %s, contains bad UTF-8 data: %s" % (kind, str(e))) if kind else \
                                             ("Encountered bad UTF-8 data: %s" % str(e)))

    @classmethod
    def _read_data(cls, data, pos):
        size = b4.unpack_from(data, pos)[0]; pos += 4
        # TODO: make a test that checks that this is enforced
        if size > len(data):
            raise BadDataLengthException("Cannot read binary data; length exceeds remaining available data")
        return data[pos:pos+size], pos+size

    @classmethod
    def _write_utf(cls, text):
        encoded_text = text.encode('utf-8')
        size = len(encoded_text)
        if size > 0xFFFF:
            raise BadDataLengthException("Cannot write UTF-8 data; length exceeds maximum size")
        result = b2.pack(size)
        result += encoded_text
        return result

    @classmethod
    def _write_data(cls, data):
        if not isinstance(data, bytes):
            raise Exception("data must be a bytes instance")
        size = len(data)
        if size > 0xFFFFFFFF:
            raise BadDataLengthException("Cannot write binary data; length exceeds maximum size")
        result = b4.pack(size)
        result += data
        return result

    @classmethod
    def _read_alias_and_timestamp(cls, data, pos):
        alias, pos = cls._read_utf(data, pos, kind="entry alias")
        timestamp = int(b8.unpack_from(data, pos)[0]); pos += 8 # milliseconds since UNIX epoch
        return (alias, timestamp, pos)

    @classmethod
    def _write_alias_and_timestamp(cls, alias, timestamp):
        result = cls._write_utf(alias)
        result += b8.pack(timestamp)
        return result

    @classmethod
    def _read_trusted_cert(cls, data, pos):
        cert_type, pos = cls._read_utf(data, pos, kind="certificate type")
        cert_data, pos = cls._read_data(data, pos)
        tcert = TrustedCertificate(cert_type, cert_data)
        return tcert, pos

    @classmethod
    def _write_trusted_cert(cls, tcert):
        # TODO: assert that tcert is a TrustedCertificate (and not a TrustedCertificateEntry) (programming error otherwise)
        result = cls._write_utf(tcert.type)
        result += cls._write_data(tcert.cert)
        return result

class AbstractKeystoreEntry(object):
    """
    Abstract superclass for keystore entries. Represents a stored value in a keystore, and its associated alias and timestamp.
    """
    def __init__(self, alias, timestamp, store_type):
        super(AbstractKeystoreEntry, self).__init__()
        self.alias = alias
        self.timestamp = timestamp
        self.store_type = store_type
        self._encrypted_form = None
        self._plaintext_form = None
        # TODO: should there be a .type field here, so users can look at the type of an entry more easily?

    @property
    def item(self):
        if not self.is_decrypted():
            raise NotYetDecryptedException("Cannot access decrypted item; entry not yet decrypted, call decrypt() with the correct password first")
        return self._plaintext_form

    def is_decrypted(self):
        """
        Returns ``True`` if the entry has already been decrypted, ``False`` otherwise.
        """
        return (not self._encrypted_form)

    def decrypt(self, key_password):
        """
        Decrypts the entry using the given password. Has no effect if the entry has already been decrypted.

        :param str key_password: The password to decrypt the entry with.
        :raises DecryptionFailureException: If the entry could not be decrypted using the given password.
        :raises UnexpectedAlgorithmException: If the entry was encrypted with an unknown or unexpected algorithm
        """
        raise NotImplementedError("Abstract method")

    def encrypt(self, key_password):
        """
        Encrypts the entry using the given password, so that it can be saved.

        :param str key_password: The password to encrypt the entry with.
        """
        raise NotImplementedError("Abstract method")

