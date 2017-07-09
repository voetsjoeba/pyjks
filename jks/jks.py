# vim: set et ai ts=4 sts=4 sw=4:
"""JKS/JCEKS file format decoder. Use in conjunction with PyOpenSSL
to translate to PEM, or load private key and certs directly into
openssl structs and wrap sockets.

Notes on Python2/3 compatibility:

Whereever possible, we rely on the 'natural' byte string
representation of each Python version, i.e. 'str' in Python2 and
'bytes' in Python3.

Python2.6+ aliases the 'bytes' type to 'str', so we can universally
write bytes(...) or b"" to get each version's natural byte string
representation.

The libraries we interact with are written to expect these natural
types in their respective Py2/Py3 versions, so this works well.

Things get slightly more complicated when we need to manipulate
individual bytes from a byte string. str[x] returns a 'str' in Python2
and an 'int' in Python3. You can't do 'int' operations on a 'str' and
vice-versa, so we need some form of common data type.  We use
bytearray() for this purpose; in both Python2 and Python3, this will
return individual elements as an 'int'.

"""

from __future__ import print_function
import struct
import hashlib
import javaobj
import time
from pyasn1.codec.der import encoder
from pyasn1_modules import rfc5208, rfc2459
from pyasn1.type import univ, namedtype
from . import rfc2898
from . import sun_crypto
from .base import *
from .util import *

try:
    from StringIO import StringIO as BytesIO  # python 2
except ImportError:
    from io import BytesIO  # python3

MAGIC_NUMBER_JKS = b4.pack(0xFEEDFEED)
MAGIC_NUMBER_JCEKS = b4.pack(0xCECECECE)
SIGNATURE_WHITENING = b"Mighty Aphrodite"

class TrustedCertEntry(AbstractKeystoreEntry):
    """Represents a trusted certificate entry in a JKS or JCEKS keystore."""

    def __init__(self, alias, timestamp, store_type, tcert):
        super(TrustedCertEntry, self).__init__(alias, timestamp, store_type)
        # TODO: check that tcert is a TrustedCertificate
        self._plaintext_form = tcert

    def decrypt(self, key_password):
        return
    def encrypt(self, key_password):
        return

class PrivateKeyEntry(AbstractKeystoreEntry):
    """Represents a private key entry in a JKS or JCEKS keystore (e.g. an RSA or DSA private key)."""

    def __init__(self, alias, timestamp, store_type, pkey, certs=None):
        super(PrivateKeyEntry, self).__init__(alias, timestamp, store_type)
        if isinstance(pkey, PrivateKey):
            self.certs = None
            self._plaintext_form = pkey
        elif isinstance(pkey, (bytes, bytearray)):
            self.certs = (certs or []) # certs are not involved in encryption/decryption, keep these separately
            self._encrypted_form = pkey
        else:
            raise Exception("Invalid private key value; must be a PrivateKey instance or an encrypted bytes form")

    def decrypt(self, key_password):
        if self.is_decrypted():
            return

        encrypted_info = None
        try:
            encrypted_info = asn1_checked_decode(self._encrypted_form, asn1Spec=rfc5208.EncryptedPrivateKeyInfo())
        except PyAsn1Error:
            raise DecryptionFailureException("Failed to decrypt data for private key '%s': not a valid PKCS#8 EncryptedPrivateKeyInfo structure", e)

        algo_id = encrypted_info['encryptionAlgorithm']['algorithm'].asTuple()
        algo_params = encrypted_info['encryptionAlgorithm']['parameters'].asOctets()
        encrypted_private_key = encrypted_info['encryptedData'].asOctets()

        plaintext = None
        try:
            if algo_id == sun_crypto.SUN_JKS_ALGO_ID:
                plaintext = sun_crypto.jks_pkey_decrypt(encrypted_private_key, key_password)

            elif algo_id == sun_crypto.SUN_JCE_ALGO_ID:
                if self.store_type != "jceks":
                    raise UnexpectedAlgorithmException("Encountered JCEKS private key protection algorithm in JKS keystore")
                # see RFC 2898, section A.3: PBES1 and definitions of AlgorithmIdentifier and PBEParameter
                params = asn1_checked_decode(algo_params, asn1Spec=rfc2898.PBEParameter())
                salt = params['salt'].asOctets()
                iteration_count = int(params['iterationCount'])
                plaintext = sun_crypto.jce_pbe_decrypt(encrypted_private_key, key_password, salt, iteration_count)
            else:
                raise UnexpectedAlgorithmException("Unknown %s private key protection algorithm: %s" % (self.store_type.upper(), algo_id))

        except (BadHashCheckException, BadPaddingException):
            raise DecryptionFailureException("Failed to decrypt data for private key '%s'; wrong password?" % self.alias)

        # In JCEKS stores, the key protection scheme is password-based encryption with PKCS#5/7 padding, so any wrong password has a 1/256
        # chance of producing a 0x01 byte as the last byte and passing the padding check but producing garbage plaintext.

        # The plaintext should be a DER-encoded PKCS#8 PrivateKeyInfo, so try to parse it as such; if that fails, then
        # either the password was wrong and we hit a 1/256 case, or the password was right and the data is genuinely corrupt.
        # In sane use cases the latter shouldn't happen, so let's assume the former.
        try:
            pk = PrivateKey(plaintext, self.certs, key_format='pkcs8')
        except BadKeyEncodingException:
            raise DecryptionFailureException("Failed to decrypt data for private key '%s'; wrong password?" % self.alias)

        self._encrypted_form = None
        self._plaintext_form = pk
        self.certs = None # PrivateKey object now contains the definitive certificate list

    def encrypt(self, key_password):
        if not self.is_decrypted():
            return

        pk = self._plaintext_form # PrivateKey instance

        ciphertext = None
        a = rfc2459.AlgorithmIdentifier()

        if self.store_type == "jks":
            ciphertext = sun_crypto.jks_pkey_encrypt(pk.key_pkcs8, key_password)
            a.setComponentByName('algorithm', sun_crypto.SUN_JKS_ALGO_ID)
            a.setComponentByName('parameters', univ.Null())

        elif self.store_type == "jceks":
            ciphertext, salt, iteration_count = sun_crypto.jce_pbe_encrypt(pk.key_pkcs8, key_password)

            pbe_params = rfc2898.PBEParameter()
            pbe_params.setComponentByName('salt', salt)
            pbe_params.setComponentByName('iterationCount', iteration_count)

            a.setComponentByName('algorithm', sun_crypto.SUN_JCE_ALGO_ID)
            a.setComponentByName('parameters', encoder.encode(pbe_params))
        else:
            raise UnsupportedKeystoreTypeException("Cannot encrypt entries of this type for storage in '%s' keystores; can only encrypt for JKS and JCEKS stores" % (self.store_type,))

        epki = rfc5208.EncryptedPrivateKeyInfo()
        epki.setComponentByName('encryptionAlgorithm', a)
        epki.setComponentByName('encryptedData', ciphertext)

        self.certs = pk.certs # TODO: write test case for the absence of this line (e.g. if the user loads a PrivateKeyEntry, grabs the PrivateKey, modifies its .certs to a different list, and then re-saves it to the store)
        self._encrypted_form = encoder.encode(epki)
        self._plaintext_form = None

class SecretKeyEntry(AbstractKeystoreEntry):
    """Represents a secret (symmetric) key entry in a JCEKS keystore (e.g. an AES or DES key)."""
    _classdesc_KR = None
    _classdesc_KRT = None
    _classdesc_SOFKP = None
    _classdesc_SKS = None

    def __init__(self, alias, timestamp, store_type, skey):
        super(SecretKeyEntry, self).__init__(alias, timestamp, store_type)
        if isinstance(skey, SecretKey):
            self._plaintext_form = skey
        elif isinstance(skey, javaobj.JavaObject):
            if not java_is_subclass(skey, "javax.crypto.SealedObject"):
                raise UnexpectedJavaTypeException("Unexpected sealed object type '%s'; not a subclass of javax.crypto.SealedObject" % skey.get_class().name)
            self._encrypted_form = skey
        else:
            raise Exception("Invalid secret key value; must be a SecretKey instance or an Java SealedObject instance")

    def decrypt(self, key_password):
        if self.is_decrypted():
            return

        plaintext = None
        sealed_obj = self._encrypted_form

        encryptedContent = None if sealed_obj.encryptedContent is None else java2bytes(sealed_obj.encryptedContent)
        encodedParams    = None if sealed_obj.encodedParams is None else java2bytes(sealed_obj.encodedParams)

        if sealed_obj.sealAlg == "PBEWithMD5AndTripleDES":
            # if the object was sealed with PBEWithMD5AndTripleDES
            # then the parameters should apply to the same algorithm
            # and not be empty or null
            if sealed_obj.paramsAlg != sealed_obj.sealAlg:
                raise UnexpectedAlgorithmException("Unexpected parameters algorithm used in SealedObject; should match sealing algorithm '%s' but found '%s'" % (sealed_obj.sealAlg, sealed_obj.paramsAlg))
            if encodedParams is None or len(encodedParams) == 0:
                raise UnexpectedJavaTypeException("No parameters found in SealedObject instance for sealing algorithm '%s'; need at least a salt and iteration count to decrypt" % sealed_obj.sealAlg)

            params_asn1 = asn1_checked_decode(encodedParams, rfc2898.PBEParameter())
            salt = params_asn1['salt'].asOctets()
            iteration_count = int(params_asn1['iterationCount'])
            try:
                plaintext = sun_crypto.jce_pbe_decrypt(encryptedContent, key_password, salt, iteration_count)
            except sun_crypto.BadPaddingException:
                raise DecryptionFailureException("Failed to decrypt data for secret key '%s'; bad password?" % self.alias)
        else:
            raise UnexpectedAlgorithmException("Unexpected algorithm used for encrypting SealedObject: sealAlg=%s" % sealed_obj.sealAlg)

        # The plaintext here is another serialized Java object; this
        # time it's an object implementing the javax.crypto.SecretKey
        # interface.  When using the default SunJCE provider, these
        # are usually either javax.crypto.spec.SecretKeySpec objects,
        # or some other specialized ones like those found in the
        # com.sun.crypto.provider package (e.g. DESKey and DESedeKey).
        #
        # Additionally, things are further complicated by the fact
        # that some of these specialized SecretKey implementations
        # (i.e. other than SecretKeySpec) implement a writeReplace()
        # method, causing Java's serialization runtime to swap out the
        # object for a completely different one at serialization time.
        # Again for SunJCE, the substitute object that gets serialized
        # is usually a java.security.KeyRep object.
        key = None
        algorithm = None

        obj, dummy = KeyStore._read_java_obj(plaintext, 0)
        clazz = obj.get_class()
        if clazz.name == "javax.crypto.spec.SecretKeySpec":
            algorithm = str(obj.algorithm) # convert from javaobj.JavaString to python native str
            key = java2bytes(obj.key)

        elif clazz.name == "java.security.KeyRep":
            assert (obj.type.constant == "SECRET"), "Expected value 'SECRET' for KeyRep.type enum value, found '%s'" % obj.type.constant
            key_bytes = java2bytes(obj.encoded)
            key_encoding = str(obj.format)
            if key_encoding == "RAW":
                pass # ok, no further processing needed
            elif key_encoding == "X.509":
                raise NotImplementedError("X.509 encoding for KeyRep objects not yet implemented")
            elif key_encoding == "PKCS#8":
                raise NotImplementedError("PKCS#8 encoding for KeyRep objects not yet implemented")
            else:
                raise UnexpectedKeyEncodingException("Unexpected key encoding '%s' found in serialized java.security.KeyRep object; expected one of 'RAW', 'X.509', 'PKCS#8'." % key_encoding)

            algorithm = str(obj.algorithm) # convert from javaobj.JavaString to python native str
            key = key_bytes
        else:
            raise UnexpectedJavaTypeException("Unexpected object of type '%s' found inside SealedObject; don't know how to handle it" % clazz.name)

        self._encrypted_form = None
        self._plaintext_form = SecretKey(key, algorithm)

    def encrypt(self, key_password):
        """
        Encrypts the Secret Key so that the keystore can be saved
        """
        if not self.is_decrypted():
            return

        sk = self._plaintext_form

        # build a plaintext Java object to hold the key and some metadata
        plaintext_obj = None
        if "DES" in sk.algorithm:
            plaintext_obj = self._java_KeyRep(sk.algorithm, sk.key, "RAW", "SECRET")
        else:
            plaintext_obj = self._java_SecretKeySpec(sk.algorithm, sk.key)

        plaintext = javaobj.dumps(plaintext_obj)

        # now encrypt the serialized plaintext object, and store the result in a SealedObjectForKeyProtector object
        ciphertext, salt, iteration_count = sun_crypto.jce_pbe_encrypt(plaintext, key_password)

        params = rfc2898.PBEParameter()
        params.setComponentByName('salt', salt)
        params.setComponentByName('iterationCount', iteration_count)
        params = encoder.encode(params)

        sealed_obj = self._java_SealedObjectForKeyProtector(ciphertext, params, "PBEWithMD5AndTripleDES", "PBEWithMD5AndTripleDES")
        self._encrypted_form = sealed_obj
        self._plaintext_form = None

    @classmethod
    def _java_SealedObjectForKeyProtector(cls, encryptedContent, encodedParams, paramsAlg, sealAlg):
        """
        Constructs and returns a javaobj.JavaObject representation of a SealedObjectForKeyProtector object with the given parameters

        :param bytes encryptedContent: The serialized underlying object, in encrypted format.
        :param bytes encodedParams: The cryptographic parameters used by the sealing Cipher, encoded in the default format
        :param str paramsAlg: Name of the encryption method (as known to Java) for which the parameters are valid.
        :param str sealAlg: Name of the encryption method (as known to Java) that was used to encrypt the serialized underlying object.
        """
        if not cls._classdesc_SOFKP:
            classdesc_SO = javaobj.JavaClass()
            classdesc_SO.name = "javax.crypto.SealedObject"
            classdesc_SO.serialVersionUID = 4482838265551344752
            classdesc_SO.flags = javaobj.JavaObjectConstants.SC_SERIALIZABLE
            classdesc_SO.fields_names = ['encodedParams', 'encryptedContent', 'paramsAlg', 'sealAlg']
            classdesc_SO.fields_types = ['[B', '[B', 'Ljava/lang/String;', 'Ljava/lang/String;']

            cls._classdesc_SOFKP = javaobj.JavaClass()
            cls._classdesc_SOFKP.name = "com.sun.crypto.provider.SealedObjectForKeyProtector"
            cls._classdesc_SOFKP.serialVersionUID = -3650226485480866989
            cls._classdesc_SOFKP.flags = javaobj.JavaObjectConstants.SC_SERIALIZABLE
            cls._classdesc_SOFKP.superclass = classdesc_SO

        obj = javaobj.JavaObject()
        obj.classdesc = cls._classdesc_SOFKP
        obj.encryptedContent = bytes2java(encryptedContent)
        obj.encodedParams = bytes2java(encodedParams)
        obj.paramsAlg = javaobj.JavaString(paramsAlg)
        obj.sealAlg = javaobj.JavaString(sealAlg)

        return obj

    @classmethod
    def _java_SecretKeySpec(cls, algorithm, key):
        if not cls._classdesc_SKS:
            cls._classdesc_SKS = javaobj.JavaClass()
            cls._classdesc_SKS.name = "javax.crypto.spec.SecretKeySpec"
            cls._classdesc_SKS.serialVersionUID = 6577238317307289933
            cls._classdesc_SKS.flags = javaobj.JavaObjectConstants.SC_SERIALIZABLE
            cls._classdesc_SKS.fields_names = ['algorithm', 'key']
            cls._classdesc_SKS.fields_types = ['Ljava/lang/String;', '[B']

        obj = javaobj.JavaObject()
        obj.classdesc = cls._classdesc_SKS
        obj.algorithm = javaobj.JavaString(algorithm)
        obj.key = bytes2java(key)

        return obj

    @classmethod
    def _java_KeyRep(cls, algorithm, encoded, xformat, xtype):
        if not cls._classdesc_KRT:
            classdesc_Enum = javaobj.JavaClass()
            classdesc_Enum.name = "java.lang.Enum"
            classdesc_Enum.serialVersionUID = 0
            classdesc_Enum.flags = javaobj.JavaObjectConstants.SC_ENUM | javaobj.JavaObjectConstants.SC_SERIALIZABLE

            cls._classdesc_KRT = javaobj.JavaClass()
            cls._classdesc_KRT.name = "java.security.KeyRep$Type"
            cls._classdesc_KRT.serialVersionUID = 0
            cls._classdesc_KRT.flags = javaobj.JavaObjectConstants.SC_ENUM | javaobj.JavaObjectConstants.SC_SERIALIZABLE
            cls._classdesc_KRT.superclass = classdesc_Enum

        if not cls._classdesc_KR:
            cls._classdesc_KR = javaobj.JavaClass()
            cls._classdesc_KR.name = "java.security.KeyRep"
            cls._classdesc_KR.serialVersionUID = -4757683898830641853
            cls._classdesc_KR.flags = javaobj.JavaObjectConstants.SC_SERIALIZABLE
            cls._classdesc_KR.fields_names = ['algorithm', 'encoded', 'format', 'type']
            cls._classdesc_KR.fields_types = ['Ljava/lang/String;', '[B', 'Ljava/lang/String;', 'Ljava/security/KeyRep$Type;']

        type_obj = javaobj.JavaEnum()
        type_obj.classdesc = cls._classdesc_KRT
        type_obj.constant = javaobj.JavaString(xtype)

        obj = javaobj.JavaObject()
        obj.classdesc = cls._classdesc_KR
        obj.algorithm = javaobj.JavaString(algorithm)
        obj.encoded = bytes2java(encoded)
        obj.format = javaobj.JavaString(xformat)
        obj.type = type_obj

        return obj

# --------------------------------------------------------------------------

class KeyStore(AbstractKeystore):
    """
    Represents a loaded JKS or JCEKS keystore.
    """
    ENTRY_TYPE_PRIVATE_KEY = 1
    ENTRY_TYPE_CERTIFICATE = 2
    ENTRY_TYPE_SECRET_KEY = 3

    def __init__(self, store_type, entries=None):
        super(KeyStore, self).__init__(store_type)
        if store_type not in ['jks', 'jceks']:
            raise UnsupportedKeystoreTypeException("The Keystore Type '%s' is not supported" % store_type)

        self.add_entries(entries or [])

    def make_entry(self, alias, item, timestamp=None):
        """
        Creates and returns a new Entry suitable for insertion into keystores of this type.
        """
        if timestamp is None:
            timestamp = int(time.time())*1000

        entry = None
        if isinstance(item, PrivateKey):
            entry = PrivateKeyEntry(alias, timestamp, self.store_type, item)
        elif isinstance(item, SecretKey):
            entry = SecretKeyEntry(alias, timestamp, self.store_type, item)
        elif isinstance(item, TrustedCertificate):
            entry = TrustedCertEntry(alias, timestamp, self.store_type, item)
        else:
            raise Exception("Don't know how to make an Entry for storing objects of type '%s' into a keystore ..." % type(item))

        return entry

    def add_entry(self, new_entry):
        if not isinstance(new_entry, AbstractKeystoreEntry):
            raise UnsupportedKeystoreEntryTypeException("This method takes entry objects, not plaintext keys/certificates or otherwise. Use .make_entry() to wrap a plaintext key/certificate in an appropriate entry object first.")

        valid_entry_types = (TrustedCertEntry, PrivateKeyEntry, SecretKeyEntry)
        if not isinstance(new_entry, valid_entry_types):
            raise UnsupportedKeystoreEntryTypeException("%s keystores cannot store entries of type '%s' -- must be one of %s" % (self.store_type.upper(), type(new_entry).__name__, [t.__name__ for t in valid_entry_types]))

        if self.store_type != "jceks" and isinstance(new_entry, SecretKeyEntry):
            raise UnsupportedKeystoreEntryTypeException("%s keystores cannot store entries of type '%s' -- only supported in JCEKS stores" % (self.store_type.upper(), type(new_entry).__name__))

        alias = new_entry.alias
        if alias in self.entries:
            raise DuplicateAliasException("Found duplicate alias: '%s'" % alias)

        self._entries.append((alias, new_entry))

    @classmethod
    def loads(cls, data, store_password, try_decrypt_keys=True):
        """Loads the given keystore file using the supplied password for
        verifying its integrity, and returns a :class:`KeyStore` instance.

        Note that entries in the store that represent some form of
        cryptographic key material are stored in encrypted form, and
        therefore require decryption before becoming accessible.

        Upon original creation of a key entry in a Java keystore,
        users are presented with the choice to either use the same
        password as the store password, or use a custom one. The most
        common choice is to use the store password for the individual
        key entries as well.

        For ease of use in this typical scenario, this function will
        attempt to decrypt each key entry it encounters with the store
        password:

         - If the key can be successfully decrypted with the store
           password, the entry is returned in its decrypted form, and
           its attributes are immediately accessible.
         - If the key cannot be decrypted with the store password, the
           entry is returned in its encrypted form, and requires a
           manual follow-up decrypt(key_password) call from the user
           before its individual attributes become accessible.

        Setting ``try_decrypt_keys`` to ``False`` disables this automatic
        decryption attempt, and returns all key entries in encrypted
        form.

        You can query whether a returned entry object has already been
        decrypted by calling the :meth:`is_decrypted` method on it.
        Attempting to access attributes of an entry that has not yet
        been decrypted will result in a
        :class:`~jks.util.NotYetDecryptedException`.

        :param bytes data: Byte string representation of the keystore
          to be loaded.
        :param str password: Keystore password string
        :param bool try_decrypt_keys: Whether to automatically try to
          decrypt any encountered key entries using the same password
          as the keystore password.

        :returns: A loaded :class:`KeyStore` instance, if the keystore
          could be successfully parsed and the supplied store password
          is correct.

          If the ``try_decrypt_keys`` parameter was set to ``True``, any
          keys that could be successfully decrypted using the store
          password have already been decrypted; otherwise, no atttempt
          to decrypt any key entries is made.

        :raises BadKeystoreFormatException: If the keystore is malformed
          in some way
        :raises UnsupportedKeystoreVersionException: If the keystore
          contains an unknown format version number
        :raises KeystoreSignatureException: If the keystore signature
          could not be verified using the supplied store password
        :raises DuplicateAliasException: If the keystore contains
          duplicate aliases
        """
        store_type = ""
        magic_number = data[:4]
        if magic_number == MAGIC_NUMBER_JKS:
            store_type = "jks"
        elif magic_number == MAGIC_NUMBER_JCEKS:
            store_type = "jceks"
        else:
            raise BadKeystoreFormatException('Not a JKS or JCEKS keystore'
                                             ' (magic number wrong; expected'
                                             ' FEEDFEED or CECECECE)')
        store = cls(store_type)

        try:
            version = b4.unpack_from(data, 4)[0]
            if version != 2:
                tmpl = 'Unsupported keystore version; expected v2, found v%r'
                raise UnsupportedKeystoreVersionException(tmpl % version)

            entries = {}

            entry_count = b4.unpack_from(data, 8)[0]
            pos = 12
            for i in range(entry_count):
                tag = b4.unpack_from(data, pos)[0]; pos += 4

                entry = None
                if tag == cls.ENTRY_TYPE_PRIVATE_KEY:
                    entry, pos = cls._read_private_key_entry(data, pos, store_type)
                elif tag == cls.ENTRY_TYPE_CERTIFICATE:
                    entry, pos = cls._read_trusted_cert_entry(data, pos, store_type)
                elif tag == cls.ENTRY_TYPE_SECRET_KEY:
                    if store_type != "jceks":
                        raise BadKeystoreFormatException("Unexpected entry tag {0} encountered in JKS keystore; only supported in JCEKS keystores".format(tag))
                    entry, pos = cls._read_secret_key_entry(data, pos, store_type)
                else:
                    raise BadKeystoreFormatException("Unexpected keystore entry tag %d", tag)

                if try_decrypt_keys:
                    try:
                        entry.decrypt(store_password)
                    except (DecryptionFailureException, IllegalPasswordCharactersException):
                        # Note: IllegalPasswordCharactersException can happen here in the case of JCEKS keystores; JCEKS stores have the restriction that key passwords
                        # must be ASCII-only, but the store password can be anything it wants. So we might get IllegalPasswordCharactersException if the store password
                        # is non-ASCII and we try to decrypt a key with it.
                        pass # ok, let user call decrypt() manually

                store.add_entries([entry])

        except struct.error as e:
            raise BadKeystoreFormatException(e)

        # check keystore integrity (uses UTF-16BE encoding of the password)
        hash_fn = hashlib.sha1
        hash_digest_size = hash_fn().digest_size

        store_password_utf16 = store_password.encode('utf-16be')
        expected_hash = hash_fn(store_password_utf16 + SIGNATURE_WHITENING + data[:pos]).digest()
        found_hash = data[pos:pos+hash_digest_size]

        if len(found_hash) != hash_digest_size:
            tmpl = "Bad signature size; found %d bytes, expected %d bytes"
            raise BadKeystoreFormatException(tmpl % (len(found_hash),
                                                     hash_digest_size))
        if expected_hash != found_hash:
            raise KeystoreSignatureException("Hash mismatch; incorrect keystore password?")

        return store

    def saves(self, store_password):
        """
        Saves the keystore so that it can be read by other applications.

        If any of the private keys are unencrypted, they will be encrypted
        with the same password as the keystore.

        :param str store_password: Password for the created keystore
          (and for any unencrypted keys)

        :returns: A byte string representation of the keystore.

        :raises UnsupportedKeystoreTypeException: If the keystore
          is of an unsupported type
        :raises UnsupportedKeystoreEntryTypeException: If the keystore
          contains an unsupported entry type
        """

        if self.store_type == 'jks':
            keystore = MAGIC_NUMBER_JKS
        elif self.store_type == 'jceks':
            keystore = MAGIC_NUMBER_JCEKS
        else:
            raise UnsupportedKeystoreTypeException("Only JKS and JCEKS keystores are supported")

        keystore += b4.pack(2) # version 2
        keystore += b4.pack(len(self._entries))

        # TODO: which alias is the authoritative one? the one in the dict or the one in the entry?
        for alias, entry in self._entries:
            # TODO: verify that entry.alias == alias (some smart ass might change the .alias on the entry after it has been inserted under key 'alias' in the store)
            entry.encrypt(store_password)

            if isinstance(entry, TrustedCertEntry):
                keystore += self._write_trusted_cert_entry(entry)
            elif isinstance(entry, PrivateKeyEntry):
                keystore += self._write_private_key_entry(entry)
            elif isinstance(entry, SecretKeyEntry):
                if self.store_type != 'jceks':
                    raise UnsupportedKeystoreEntryTypeException('Secret Key only allowed in JCEKS keystores')
                keystore += self._write_secret_key_entry(entry)
            else:
                raise UnsupportedKeystoreEntryTypeException("Unknown entry type in keystore")

        hash_fn = hashlib.sha1
        store_password_utf16 = store_password.encode('utf-16be')
        hash = hash_fn(store_password_utf16 + SIGNATURE_WHITENING + keystore).digest()
        keystore += hash

        return keystore

    @property
    def cert_entries(self):
        """A subset of the :attr:`entries` dictionary, filtered down to only
        those entries of type :class:`TrustedCertEntry`."""
        return dict([(a, e) for a, e in self.entries.items()
                     if isinstance(e, TrustedCertEntry)])

    @property
    def secret_key_entries(self):
        """A subset of the :attr:`entries` dictionary, filtered down to only
        those entries of type :class:`SecretKeyEntry`."""
        return dict([(a, e) for a, e in self.entries.items()
                     if isinstance(e, SecretKeyEntry)])

    @property
    def private_key_entries(self):
        """A subset of the :attr:`entries` dictionary, filtered down to only
        those entries of type :class:`PrivateKeyEntry`."""
        return dict([(a, e) for a, e in self.entries.items()
                     if isinstance(e, PrivateKeyEntry)])

    @classmethod
    def _read_trusted_cert_entry(cls, data, pos, store_type):
        alias, timestamp, pos = cls._read_alias_and_timestamp(data, pos)
        tcert, pos            = cls._read_trusted_cert(data, pos)
        entry = TrustedCertEntry(alias, timestamp, store_type, tcert)
        return entry, pos

    @classmethod
    def _read_private_key_entry(cls, data, pos, store_type):
        alias, timestamp, pos = cls._read_alias_and_timestamp(data, pos)
        ber_data, pos         = cls._read_data(data, pos)
        chain_len             = b4.unpack_from(data, pos)[0]; pos += 4

        cert_chain = []
        for j in range(chain_len):
            tcert, pos = cls._read_trusted_cert(data, pos)
            cert_chain.append(tcert)

        entry = PrivateKeyEntry(alias, timestamp, store_type, ber_data, certs=cert_chain)
        return entry, pos

    @classmethod
    def _read_secret_key_entry(cls, data, pos, store_type):
        # SecretKeys are stored in the key store file through Java's
        # serialization mechanism, i.e. as an actual serialized Java
        # object embedded inside the file. The objects that get stored
        # are not the SecretKey instances themselves though, as that
        # would trivially expose the key without the need for a
        # passphrase to gain access to it.
        #
        # Instead, an object of type javax.crypto.SealedObject is
        # written. The purpose of this class is specifically to
        # securely serialize objects that contain secret values by
        # applying a password-based encryption scheme to the
        # serialized form of the object to be protected. Only the
        # resulting ciphertext is then stored by the serialized form
        # of the SealedObject instance.
        #
        # To decrypt the SealedObject, the correct passphrase must be
        # given to be able to decrypt the underlying object's
        # serialized form.  Once decrypted, one more de-serialization
        # will result in the original object being restored.
        #
        # The default key protector used by the SunJCE provider
        # returns an instance of type SealedObjectForKeyProtector, a
        # (direct) subclass of SealedObject, which uses Java's
        # custom/unpublished PBEWithMD5AndTripleDES algorithm.
        #
        # Class member structure:
        #
        # SealedObjectForKeyProtector:
        #   static final long serialVersionUID = -3650226485480866989L;
        #
        # SealedObject:
        #   static final long serialVersionUID = 4482838265551344752L;
        #   private byte[] encryptedContent;         # The serialized underlying object, in encrypted format.
        #   private String sealAlg;                  # The algorithm that was used to seal this object.
        #   private String paramsAlg;                # The algorithm of the parameters used.
        #   protected byte[] encodedParams;          # The cryptographic parameters used by the sealing Cipher, encoded in the default format.
        alias, timestamp, pos = cls._read_alias_and_timestamp(data, pos)
        sealed_obj, pos = cls._read_java_obj(data, pos, ignore_remaining_data=True)

        entry = SecretKeyEntry(alias, timestamp, store_type, sealed_obj)
        return entry, pos

    @classmethod
    def _read_java_obj(cls, data, pos, ignore_remaining_data=False):
        data_stream = BytesIO(data[pos:])
        obj = javaobj.load(data_stream, ignore_remaining_data=ignore_remaining_data)
        obj_size = data_stream.tell()

        return obj, pos + obj_size

    @classmethod
    def _write_private_key_entry(cls, entry):
        result = b4.pack(cls.ENTRY_TYPE_PRIVATE_KEY)
        result += cls._write_alias_and_timestamp(entry.alias, entry.timestamp)
        result += cls._write_data(entry._encrypted_form)

        result += b4.pack(len(entry.certs))
        for tcert in entry.certs:
            result += cls._write_trusted_cert(tcert)

        return result

    @classmethod
    def _write_trusted_cert_entry(cls, entry):
        result = b4.pack(cls.ENTRY_TYPE_CERTIFICATE)
        result += cls._write_alias_and_timestamp(entry.alias, entry.timestamp)
        result += cls._write_trusted_cert(entry.item)
        return result

    @classmethod
    def _write_secret_key_entry(cls, entry):
        result = b4.pack(cls.ENTRY_TYPE_SECRET_KEY)
        result += cls._write_alias_and_timestamp(entry.alias, entry.timestamp)
        result += javaobj.dumps(entry._encrypted_form)
        return result

