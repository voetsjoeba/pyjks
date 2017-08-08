# vim: set et ai ts=4 sts=4 sw=4:
from .util import *

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

    def save(self, filename, store_password, entry_passwords=None):
        """
        Convenience wrapper function; calls the :func:`saves`
        and saves the content to a file.
        """
        with open(filename, 'wb') as file:
            keystore_bytes = self.saves(store_password, entry_passwords=entry_passwords)
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
        size = len(data)
        if size > 0xFFFFFFFF:
            raise BadDataLengthException("Cannot write binary data; length exceeds maximum size")
        result = b4.pack(size)
        result += data
        return result

class AbstractKeystoreEntry(object):
    """Abstract superclass for keystore entries."""
    def __init__(self, **kwargs):
        super(AbstractKeystoreEntry, self).__init__()
        self.store_type = kwargs.get("store_type")
        self.alias = kwargs.get("alias")
        self.timestamp = kwargs.get("timestamp")

    @classmethod
    def new(cls, alias):
        """
        Helper function to create a new KeyStoreEntry.
        """
        raise NotImplementedError("Abstract method")

    def is_decrypted(self):
        """
        Returns ``True`` if the entry has already been decrypted, ``False`` otherwise.
        """
        raise NotImplementedError("Abstract method")

    def decrypt(self, key_password):
        """
        Decrypts the entry using the given password. Has no effect if the entry has already been decrypted.

        :param str key_password: The password to decrypt the entry with.
        :raises DecryptionFailureException: If the entry could not be decrypted using the given password.
        :raises UnexpectedAlgorithmException: If the entry was encrypted with an unknown or unexpected algorithm
        """
        raise NotImplementedError("Abstract method")

    def _encrypt_for(self, store_type, key_password):
        """
        Encrypts the entry to be saved to a store of the given type, using the given password.

        :param str key_password: The password to encrypt the entry with.
        """
        raise NotImplementedError("Abstract method")

