# vim: set et ai ts=4 sts=4 sw=4:
import struct
import hashlib
from pyasn1_modules import rfc5208, rfc2459
from Crypto.Hash import HMAC, SHA
from .util import *
from .base import *
from . import rfc7292

# --- VALUE TYPES ---------------------------------------------------------------

class BksKey(object):
    """
    Wrapper for different kinds of non-encrypted cryptographic keys found in BKS keystores.
    """
    KEY_TYPE_PRIVATE = 0
    KEY_TYPE_PUBLIC = 1
    KEY_TYPE_SECRET = 2

    def __init__(self, type, format, algorithm, key, certs=None):
        super(BksKey, self).__init__()
        self.type = type
        self.algorithm = algorithm

        if self.type == self.KEY_TYPE_PRIVATE:
            if format not in ["PKCS8", "PKCS#8"]:
                raise UnexpectedKeyEncodingException("Unexpected encoding for private key entry: '%s'" % (format,))
            self.key = PrivateKey(key, certs or [], key_format='pkcs8')

        elif self.type == self.KEY_TYPE_PUBLIC:
            if format not in ["X.509", "X509"]:
                raise UnexpectedKeyEncodingException("Unexpected encoding for public key entry: '%s'" % (format,))
            self.key = PublicKey(key)

        elif self.type == self.KEY_TYPE_SECRET:
            if format != "RAW":
                raise UnexpectedKeyEncodingException("Unexpected encoding for secret key entry: '%s'" % (format,))
            self.key = SecretKey(key, algorithm)

        else:
            raise UnexpectedKeyEncodingException("Key type %r not recognized" % (self.type,))

    @classmethod
    def create_from(cls, obj):
        if isinstance(obj, PrivateKey):
            return BksKey(cls.KEY_TYPE_PRIVATE, "PKCS8", cls._oid2algname(obj.algorithm_oid), obj.key_pkcs8, certs=obj.certs)
        elif isinstance(obj, PublicKey):
            return BksKey(cls.KEY_TYPE_PUBLIC, "X.509", cls._oid2algname(obj.algorithm_oid), obj.key_info)
        elif isinstance(obj, SecretKey):
            return BksKey(cls.KEY_TYPE_SECRET, "RAW", obj.algorithm, obj.key)
        else:
            raise ValueError("Don't know how to create a BksKey for objects of type %s" % (type(obj),))

    @classmethod
    def _oid2algname(cls, oid):
        if oid == rfc2459.rsaEncryption.asTuple():
            return "RSA"
        elif oid == rfc2459.id_dsa.asTuple():
            return "DSA"
        else:
            return ".".join(str(x) for x in obj.algorithm_oid)

    @classmethod
    def type2str(cls, t):
        """
        Returns a string representation of the given key type. Returns one of ``PRIVATE``, ``PUBLIC`` or ``SECRET``, or ``None``
        if no such key type is known.

        :param int t: Key type constant. One of :const:`KEY_TYPE_PRIVATE`, :const:`KEY_TYPE_PUBLIC`, :const:`KEY_TYPE_SECRET`.
        """
        if t == cls.KEY_TYPE_PRIVATE:
            return "PRIVATE"
        elif t == cls.KEY_TYPE_PUBLIC:
            return "PUBLIC"
        elif t == cls.KEY_TYPE_SECRET:
            return "SECRET"
        return None

# --- ENTRY TYPES -------------------------------------------------

class AbstractBksEntry(AbstractKeystoreEntry):
    """
    BKS entries are similar to JKS ones, but can additionally store an arbitrary number of public certificates associated with the key,
    regardless of the underlying stored object (even if the underlying object is itself a certificate).
    """
    def __init__(self, alias, timestamp, store_type, cert_chain):
        super(AbstractBksEntry, self).__init__(alias, timestamp, store_type)
        self.cert_chain = cert_chain

class BksTrustedCertEntry(AbstractBksEntry):
    """
    Represents a trusted certificate entry in a BKS or UBER keystore.
    Note that even entries storing certificates can have an associated chain of certificates (may be empty).
    """
    def __init__(self, alias, timestamp, store_type, cert_chain, tcert):
        super(BksTrustedCertEntry, self).__init__(alias, timestamp, store_type, cert_chain)
        # TODO: check that tcert is a TrustedCertificate
        self._plaintext_form = tcert

    def is_decrypted(self):
        return True
    def decrypt(self, key_password):
        return
    def encrypt(self, key_password):
        return

class BksKeyEntry(AbstractBksEntry): # TODO: consider renaming this to BksPlainKeyEntry
    """
    Deprecated entry type storing BksKey objects in non-encrypted form.
    Has been long since superceded by :class:`BksSealedKeyEntry` entries and are no longer retrievable or producable in recent BC versions,
    but may exceptionally appear in (very) old keystores.
    """
    def __init__(self, alias, timestamp, store_type, cert_chain, bkskey):
        super(BksKeyEntry, self).__init__(alias, timestamp, store_type, cert_chain)
        self._plaintext_form = bkskey

    def is_decrypted(self):
        return True
    def decrypt(self, key_password):
        pass
    def encrypt(self, key_password):
        pass

class BksSecretKeyEntry(AbstractBksEntry): # TODO: consider renaming this to SecretValueEntry, since it's arbitrary secret data
    """
    Conceptually similar to, but not to be confused with, :class:`BksKeyEntry` objects of type :const:`KEY_TYPE_SECRET`:

      - :class:`BksSecretKeyEntry` objects store the result of arbitrary user-supplied byte[]s, which, per the Java Keystore SPI, keystores are
        obligated to assume have already been protected by the user in some unspecified way. Because of this assumption, no password is
        provided for these entries when adding them to the keystore, and keystores are thus forced to store these bytes as-is.

        Produced by a call to ``KeyStore.setKeyEntry(String alias, byte[] key, Certificate[] chain)`` call.

        The bouncycastle project appears to have completely abandoned these entry types well over a decade ago now, and it is no
        longer possible to retrieve these entries through the Java APIs in any (remotely) recent BC version.

      - :class:`BksKeyEntry` objects of type :const:`KEY_TYPE_SECRET` store the result of a getEncoded() call on proper Java objects of type SecretKey.

        Produced by a call to ``KeyStore.setKeyEntry(String alias, Key key, char[] password, Certificate[] chain)``.

        The difference here is that the KeyStore implementation knows it's getting a proper (Secret)Key Java object, and can decide
        for itself how to store it given the password supplied by the user. I.e., in this version of setKeyEntry it is left up to
        the keystore implementation to encode and protect the supplied Key object, instead of in advance by the user.
    """
    def __init__(self, alias, timestamp, store_type, cert_chain, skey):
        super(BksSecretKeyEntry, self).__init__(alias, timestamp, store_type, cert_chain)
        # TODO: check that skey is a bytes or bytearray (no corresponding SecretKey instance, BKS doesn't store the algorithm name ...)
        self._plaintext_form = skey

    def is_decrypted(self):
        return True
    def decrypt(self, key_password):
        pass
    def encrypt(self, key_password):
        pass

class BksSealedKeyEntry(AbstractBksEntry):
    """
    Entry type storing a PBEWithSHAAnd3-KeyTripleDES-CBC-encrypted :class:`BksKey`. The contained key type is unknown until decrypted.
    """
    def __init__(self, alias, timestamp, store_type, cert_chain, bkskey):
        super(BksSealedKeyEntry, self).__init__(alias, timestamp, store_type, cert_chain)
        if isinstance(bkskey, BksKey):
            self._plaintext_form = bkskey
        elif isinstance(bkskey, (bytes, bytearray)):
            self._encrypted_form = bkskey
        else:
            raise Exception("derp")

    def is_decrypted(self):
        return (not self._encrypted_form)

    def decrypt(self, key_password):
        if self.is_decrypted():
            return

        pos = 0
        data = self._encrypted_form

        salt, pos = BksKeyStore._read_data(data, pos)
        iteration_count = b4.unpack_from(data, pos)[0]; pos += 4
        encrypted_blob = data[pos:]

        # The intention of the BKS entry decryption routine in BcKeyStoreSpi.StoreEntry.getObject(char[] password) appears to be:
        #  - try to decrypt with "PBEWithSHAAnd3-KeyTripleDES-CBC" first (1.2.840.113549.1.12.1.3);
        #  - if that fails, try again with "BrokenPBEWithSHAAnd3-KeyTripleDES-CBC";
        #  - if that still fails, try again with "OldPBEWithSHAAnd3-KeyTripleDES-CBC"
        #  - give up with an UnrecoverableKeyException
        #
        # However, at the time of writing (bcprov-jdk15on-1.53 and 1.54), the second and third cases can never successfully execute
        # because their implementation requests non-existent SecretKeyFactory objects for the Broken/Old algorithm names.
        # Inquiry through the BC developer mailing list tells us that this is indeed old functionality that has been retired long ago
        # and is not expected to be operational anymore, and should be cleaned up.
        #
        # So in practice, the real behaviour is:
        #  - try to decrypt with "PBEWithSHAAnd3-KeyTripleDES-CBC" (1.2.840.113549.1.12.1.3);
        #  - give up with an UnrecoverableKeyException
        #
        # Implementation classes:
        #         PBEWithSHAAnd3-KeyTripleDES-CBC  ->  org.bouncycastle.jcajce.provider.symmetric.DESede$PBEWithSHAAndDES3Key
        #   BrokenPBEWithSHAAnd3-KeyTripleDES-CBC  ->  org.bouncycastle.jce.provider.BrokenJCEBlockCipher$BrokePBEWithSHAAndDES3Key
        #      OldPBEWithSHAAnd3-KeyTripleDES-CBC  ->  org.bouncycastle.jce.provider.BrokenJCEBlockCipher$OldPBEWithSHAAndDES3Key
        #
        try:
            decrypted = rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(encrypted_blob, key_password, salt, iteration_count)
        except BadDataLengthException:
            raise BadKeystoreFormatException("Bad BKS entry format: %s" % str(e))
        except BadPaddingException:
            raise DecryptionFailureException("Failed to decrypt data for key '%s'; wrong password?" % self.alias)

        # the plaintext content of a SealedKeyEntry is a BksKey
        bkskey, dummy = BksKeyStore._read_bks_key(decrypted, 0)

        # if the BksKey we decrypted contains a PrivateKey, we should populate its .certs field with the chain we have at the entry level
        if bkskey.type == BksKey.KEY_TYPE_PRIVATE:
            bkskey.key.certs = self.cert_chain[:] # shallow copy

        self._plaintext_form = bkskey
        self._encrypted_form = None

    decrypt.__doc__ = AbstractBksEntry.decrypt.__doc__
    is_decrypted.__doc__ = AbstractBksEntry.is_decrypted.__doc__


class BksKeyStore(AbstractKeystore):
    """
    Bouncycastle "BKS" keystore parser. Supports both the current V2 and old V1 formats.
    """
    ENTRY_TYPE_CERTIFICATE = 1    # maps to BksTrustedCertEntry
    ENTRY_TYPE_KEY = 2            # maps to BksKeyEntry;           plaintext key entry as would otherwise be stored inside a sealed entry (type 4); no longer supported at the time of writing (BC 1.54)
    ENTRY_TYPE_SECRET = 3         # maps to BksSecreyKeyEntry      for keys that were added to the store in already-protected form; can be arbitrary data
    ENTRY_TYPE_SEALED = 4         # maps to BksSealedKeyEntry      for keys that were protected by the BC keystore implementation upon adding

    def __init__(self, store_type, entries, version=2):
        super(BksKeyStore, self).__init__(store_type, entries)
        self.version = version
        """Version of the keystore format, if loaded."""

    def __init__(self, store_type, entries=None, version=2):
        super(BksKeyStore, self).__init__(store_type)
        self.version = version
        if store_type not in ['bks']:
            raise UnsupportedKeystoreTypeException("The Keystore Type '%s' is not supported" % store_type)

        self.add_entries(entries or [])

    def make_entry(self, alias, item, timestamp=None):
        """
        Creates and returns a new Entry suitable for insertion into keystores of this type.
        """
        if timestamp is None:
            timestamp = int(time.time())*1000

        entry = None
        if isinstance(item, BksKey):
            # BksKeys can get wrapped by either a BksSealedKeyEntry or a BksKeyEntry, but BksKeyEntries are unencrypted and no longer supported,
            # so clearly we want to create BksSealedKeyEntries for these
            entry = BksSealedKeyEntry(alias, timestamp, self.store_type, item)
        elif isinstance(item, (PrivateKey, PublicKey, SecretKey)):
            bkskey = BksKey.create_from(item)
            entry = BksSealedKeyEntry(alias, timestamp, self.store_type, bkskey)
        elif isinstance(item, TrustedCertificate):
            entry = BksTrustedCertEntry(alias, timestamp, self.store_type, item)
        else:
            raise Exception("Don't know how to make an Entry for storing objects of type '%s' into a keystore ..." % type(item))

        return entry

    def add_entry(self, new_entry):
        if not isinstance(new_entry, AbstractBksEntry):
            raise UnsupportedKeystoreEntryTypeException("This method takes entry objects, not plaintext keys/certificates or otherwise. Use .make_entry() to wrap a plaintext key/certificate in an appropriate entry object first.")

        valid_entry_types = (BksTrustedCertEntry, BksKeyEntry, BksSecretKeyEntry, BksSealedKeyEntry)
        if not isinstance(new_entry, valid_entry_types):
            raise UnsupportedKeystoreEntryTypeException("%s keystores cannot store entries of type '%s' -- must be one of %s" % (self.store_type.upper(), type(new_entry).__name__, [t.__name__ for t in valid_entry_types]))

        alias = new_entry.alias
        if alias in self.entries:
            raise DuplicateAliasException("Found duplicate alias: '%s'" % alias)

        self._entries.append((alias, new_entry))

    # TODO: rename to cert_entries
    @property
    def cert_entries(self):
        """A subset of the :attr:`entries` dictionary, filtered down to only
        those entries of type :class:`BksTrustedCertEntry`."""
        return dict([(a, e) for a, e in self.entries.items()
                     if isinstance(e, BksTrustedCertEntry)])

    # TODO: rename to secret_key_entries
    @property
    def secret_key_entries(self):
        """A subset of the :attr:`entries` dictionary, filtered down to only
        those entries of type :class:`BksSecretKeyEntry`."""
        return dict([(a, e) for a, e in self.entries.items()
                     if isinstance(e, BksSecretKeyEntry)])

    # TODO: rename to sealed_key_entries
    @property
    def sealed_key_entries(self):
        """A subset of the :attr:`entries` dictionary, filtered down to only
        those entries of type :class:`BksSealedKeyEntry`."""
        return dict([(a, e) for a, e in self.entries.items()
                     if isinstance(e, BksSealedKeyEntry)])

    # TODO: rename to plain_key_entries
    @property
    def plain_key_entries(self):
        """A subset of the :attr:`entries` dictionary, filtered down to only
        those entries of type :class:`BksKeyEntry`."""
        return dict([(a, e) for a, e in self.entries.items()
                     if isinstance(e, BksKeyEntry)])

    @classmethod
    def loads(cls, data, store_password, try_decrypt_keys=True):
        """
        See :meth:`jks.jks.KeyStore.loads`.

        :param bytes data: Byte string representation of the keystore to be loaded.
        :param str password: Keystore password string
        :param bool try_decrypt_keys: Whether to automatically try to decrypt any encountered key entries using the same password
                                      as the keystore password.

        :returns: A loaded :class:`BksKeyStore` instance, if the keystore could be successfully parsed and the supplied store password is correct.

                  If the ``try_decrypt_keys`` parameters was set to ``True``, any keys that could be successfully decrypted using the
                  store password have already been decrypted; otherwise, no atttempt to decrypt any key entries is made.

        :raises BadKeystoreFormatException: If the keystore is malformed in some way
        :raises UnsupportedKeystoreVersionException: If the keystore contains an unknown format version number
        :raises KeystoreSignatureException: If the keystore signature could not be verified using the supplied store password
        :raises DuplicateAliasException: If the keystore contains duplicate aliases
        """
        try:
            pos = 0
            version = b4.unpack_from(data, pos)[0]; pos += 4
            if version not in [1,2]:
                raise UnsupportedKeystoreVersionException("Unsupported BKS keystore version; only V1 and V2 supported, found v"+repr(version))

            salt, pos = cls._read_data(data, pos)
            iteration_count = b4.unpack_from(data, pos)[0]; pos += 4

            store_type = "bks"
            entries, size = cls._load_bks_entries(data[pos:], store_type, store_password, try_decrypt_keys=try_decrypt_keys)

            hmac_fn = hashlib.sha1
            hmac_digest_size = hmac_fn().digest_size
            hmac_key_size = hmac_digest_size*8 if version != 1 else hmac_digest_size
            hmac_key = rfc7292.derive_key(hmac_fn, rfc7292.PURPOSE_MAC_MATERIAL, store_password, salt, iteration_count, hmac_key_size//8)

            store_data = data[pos:pos+size]
            store_hmac = data[pos+size:pos+size+hmac_digest_size]
            if len(store_hmac) != hmac_digest_size:
                raise BadKeystoreFormatException("Bad HMAC size; found %d bytes, expected %d bytes" % (len(store_hmac), hmac_digest_size))

            hmac = HMAC.new(hmac_key, digestmod=SHA)
            hmac.update(store_data)

            computed_hmac = hmac.digest()
            if store_hmac != computed_hmac:
                raise KeystoreSignatureException("Hash mismatch; incorrect keystore password?")

            return cls(store_type, entries=entries, version=version)

        except struct.error as e:
            raise BadKeystoreFormatException(e)

    @classmethod
    def _load_bks_entries(cls, data, store_type, store_password, try_decrypt_keys=False):
        entries = []
        pos = 0
        while pos < len(data):
            _type = b1.unpack_from(data, pos)[0]; pos += 1
            if _type == 0:
                break

            entry = None
            if _type == cls.ENTRY_TYPE_CERTIFICATE: # certificate
                entry, pos = cls._read_bks_cert_entry(data, pos, store_type)
            elif _type == cls.ENTRY_TYPE_KEY:       # key: plaintext key entry, i.e. same as sealed key but without the PBEWithSHAAnd3KeyTripleDESCBC layer
                entry, pos = cls._read_bks_key_entry(data, pos, store_type)
            elif _type == cls.ENTRY_TYPE_SECRET:    # secret key: opaque arbitrary data blob, stored as-is by the keystore; can be anything (assumed to already be protected when supplied).
                entry, pos = cls._read_bks_secret_key_entry(data, pos, store_type)
            elif _type == cls.ENTRY_TYPE_SEALED:    # sealed key; a well-formatted certificate, private key or public key, encrypted by the BKS implementation with a standard algorithm at save time
                entry, pos = cls._read_bks_sealed_entry(data, pos, store_type)
            else:
                raise BadKeystoreFormatException("Unexpected keystore entry type %d", tag)

            if try_decrypt_keys:
                try:
                    entry.decrypt(store_password)
                except DecryptionFailureException:
                    pass # ok, let user call .decrypt() manually afterwards

            entries.append(entry)

        return (entries, pos)

    @classmethod
    def _read_alias_timestamp_chain(cls, data, pos):
        alias, timestamp, pos = cls._read_alias_and_timestamp(data, pos)
        chain_length = b4.unpack_from(data, pos)[0]; pos += 4

        cert_chain = []
        for n in range(chain_length):
            entry, pos = cls._read_trusted_cert(data, pos)
            cert_chain.append(entry)

        return (alias, timestamp, cert_chain, pos)

    @classmethod
    def _read_bks_cert_entry(cls, data, pos, store_type):
        alias, timestamp, cert_chain, pos = cls._read_alias_timestamp_chain(data, pos)
        tcert, pos = cls._read_trusted_cert(data, pos)
        entry = BksTrustedCertEntry(alias, timestamp, store_type, cert_chain, tcert)
        return entry, pos

    @classmethod
    def _read_bks_key_entry(cls, data, pos, store_type):
        alias, timestamp, cert_chain, pos = cls._read_alias_timestamp_chain(data, pos)
        bkskey, pos = cls._read_bks_key(data, pos)
        entry = BksKeyEntry(alias, timestamp, store_type, cert_chain, bkskey)
        return entry, pos

    @classmethod
    def _read_bks_key(cls, data, pos):
        type           = b1.unpack_from(data, pos)[0]; pos += 1
        format, pos    = cls._read_utf(data, pos, kind="key format")
        algorithm, pos = cls._read_utf(data, pos, kind="key algorithm")
        encoded, pos   = cls._read_data(data, pos)

        bkskey = BksKey(type, format, algorithm, encoded)
        return bkskey, pos

    @classmethod
    def _read_bks_secret_key_entry(cls, data, pos, store_type):
        alias, timestamp, cert_chain, pos = cls._read_alias_timestamp_chain(data, pos)
        secret_data, pos = cls._read_data(data, pos)
        entry = BksSecretKeyEntry(alias, timestamp, store_type, cert_chain, secret_data)
        return entry, pos

    @classmethod
    def _read_bks_sealed_entry(cls, data, pos, store_type):
        alias, timestamp, cert_chain, pos = cls._read_alias_timestamp_chain(data, pos)
        sealed_data, pos = cls._read_data(data, pos)
        entry = BksSealedKeyEntry(alias, timestamp, store_type, cert_chain, sealed_data)
        return entry, pos

class UberKeyStore(BksKeyStore):
    """
    BouncyCastle "UBER" keystore format parser.
    """
    def __init__(self, store_type, entries=None, version=2):
        super(BksKeyStore, self).__init__(store_type)
        self.version = version
        if store_type not in ['uber']:
            raise UnsupportedKeystoreTypeException("The Keystore Type '%s' is not supported" % store_type)

        self.add_entries(entries or [])

    @classmethod
    def loads(cls, data, store_password, try_decrypt_keys=True):
        """
        See :meth:`jks.jks.KeyStore.loads`.

        :param bytes data: Byte string representation of the keystore to be loaded.
        :param str password: Keystore password string
        :param bool try_decrypt_keys: Whether to automatically try to decrypt any encountered key entries using the same password
                                      as the keystore password.

        :returns: A loaded :class:`UberKeyStore` instance, if the keystore could be successfully parsed and the supplied store password is correct.

                  If the ``try_decrypt_keys`` parameters was set to ``True``, any keys that could be successfully decrypted using the
                  store password have already been decrypted; otherwise, no atttempt to decrypt any key entries is made.

        :raises BadKeystoreFormatException: If the keystore is malformed in some way
        :raises UnsupportedKeystoreVersionException: If the keystore contains an unknown format version number
        :raises KeystoreSignatureException: If the keystore signature could not be verified using the supplied store password
        :raises DecryptionFailureException: If the keystore contents could not be decrypted using the supplied store password
        :raises DuplicateAliasException: If the keystore contains duplicate aliases
        """
        # Uber keystores contain the same entry data as BKS keystores, except they wrap it differently:
        #    BKS  = BKS_store || HMAC-SHA1(BKS_store)
        #    UBER = PBEWithSHAAndTwofish-CBC(BKS_store || SHA1(BKS_store))
        #
        # where BKS_store represents the entry format shared by both keystore types.
        #
        # The Twofish key size is 256 bits, the PBE key derivation scheme is that as outlined by PKCS#12 (RFC 7292),
        # and the padding scheme for the Twofish cipher is PKCS#7.
        try:
            pos = 0
            version = b4.unpack_from(data, pos)[0]; pos += 4
            if version != 1:
                raise UnsupportedKeystoreVersionException('Unsupported UBER keystore version; only v1 supported, found v'+repr(version))

            salt, pos = cls._read_data(data, pos)
            iteration_count = b4.unpack_from(data, pos)[0]; pos += 4

            encrypted_bks_store = data[pos:]
            try:
                decrypted = rfc7292.decrypt_PBEWithSHAAndTwofishCBC(encrypted_bks_store, store_password, salt, iteration_count)
            except BadDataLengthException as e:
                raise BadKeystoreFormatException("Bad UBER keystore format: %s" % str(e))
            except BadPaddingException as e:
                raise DecryptionFailureException("Failed to decrypt UBER keystore: bad password?")

            # Note: we can assume that the hash must be present at the last 20 bytes of the decrypted data (i.e. without first
            # parsing through to see where the entry data actually ends), because valid UBER keystores generators should not put
            # any trailing bytes after the hash prior to encrypting.
            hash_fn = hashlib.sha1
            hash_digest_size = hash_fn().digest_size

            bks_store = decrypted[:-hash_digest_size]
            bks_hash  = decrypted[-hash_digest_size:]
            if len(bks_hash) != hash_digest_size:
                raise BadKeystoreFormatException("Insufficient signature bytes; found %d bytes, expected %d bytes" % (len(bks_hash), hash_digest_size))
            if hash_fn(bks_store).digest() != bks_hash:
                raise KeystoreSignatureException("Hash mismatch; incorrect keystore password?")

            store_type = "uber"
            entries, size = cls._load_bks_entries(bks_store, store_type, store_password, try_decrypt_keys=try_decrypt_keys)
            return cls(store_type, entries=entries, version=version)

        except struct.error as e:
            raise BadKeystoreFormatException(e)

