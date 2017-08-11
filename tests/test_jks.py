#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:
"""
Tests for pyjks.
Note: run 'mvn test' in the tests/java directory to reproduce keystore files (requires a working Maven installation)
"""

from __future__ import print_function
import os
import sys
import hashlib
import time
import subprocess
import json
import base64
import javaobj
from pyasn1.error import PyAsn1Error
from pyasn1.codec.der import encoder
from pyasn1_modules import rfc5208, rfc2459

import jks
from jks.util import *
from . import expected

if sys.version_info < (2, 7):
    import unittest2 as unittest # Python 2.6's unittest doesn't have any functionality for skipping tests
else:
    import unittest

try:
    long
except:
    long = int

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
KS_PATH = os.path.join(CUR_PATH, 'keystores')
JAVA_TESTCASES_PATH = os.path.join(CUR_PATH, "java")

java_dumper_jar_path = None # None initially; set to path to JAR file on module setup (if successfully built)
java_dumper_main_class = "org.pyjks.KeystoreDumper"

# subprocess.check_output does not exist in Python 2.6; use 2.7's implementation
if "check_output" not in dir(subprocess):
    def f(*popenargs, **kwargs):
        if 'stdout' in kwargs:
            raise ValueError('stdout argument not allowed, it will be overridden.')
        process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
        output, unused_err = process.communicate()
        retcode = process.poll()
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise subprocess.CalledProcessError(retcode, cmd)
        return output
    subprocess.check_output = f

def setUpModule():
    global java_dumper_jar_path
    with cd(JAVA_TESTCASES_PATH):
        try:
            # See if we can build the KeystoreDumper JAR.
            # Note: we skip running the test cases, because those will produce new randomized keystore input files for the test cases.
            # While harmless, the generated keystores are checked into source control, so running the test cases would just produce git status noise.
            subprocess.check_output(["mvn", "package", "-DskipTests"])
            java_dumper_jar_path = os.path.abspath("target/pyjks-1.0.0-jar-with-dependencies.jar")
        except:
            return # java_dumper_jar_path remains None

class AbstractTest(unittest.TestCase):
    def find_private_key(self, ks, alias):
        pk = ks.entries[alias]
        if not isinstance(pk, jks.PrivateKeyEntry):
            self.fail("Private key entry not found: %s" % alias)

        if pk.is_decrypted():
            self.assertTrue(isinstance(pk.pkey, bytes))
            self.assertTrue(isinstance(pk.pkey_pkcs8, bytes))
        self.assertTrue(isinstance(pk.cert_chain, list))
        self.assertTrue(all(isinstance(c[1], bytes) for c in pk.cert_chain))
        return pk

    def find_secret_key(self, ks, alias):
        sk = ks.entries[alias]
        if not isinstance(sk, jks.SecretKeyEntry):
            self.fail("Secret key entry not found: %s" % alias)

        if sk.is_decrypted():
            self.assertTrue(isinstance(sk.key, bytes))
        return sk

    def find_cert(self, ks, alias):
        c = ks.entries[alias]
        if not isinstance(c, jks.TrustedCertEntry):
            self.fail("Certificate entry not found: %s" % alias)

        self.assertTrue(isinstance(c.cert, bytes))
        self.assertTrue(isinstance(c.type, py23basestring))
        return c

    def check_cert_equal(self, cert, cert_type, cert_data):
        self.assertEqual(cert.type, cert_type)
        self.assertEqual(cert.cert, cert_data)

    def check_pkey_and_certs_equal(self, pk, algorithm_oid, pkey_pkcs8, certs):
        self.assertEqual(pk.algorithm_oid, algorithm_oid)
        self.assertEqual(pk.pkey_pkcs8, pkey_pkcs8)
        self.assertEqual(len(pk.cert_chain), len(certs))
        for i in range(len(certs)):
            self.assertEqual(pk.cert_chain[i][1], certs[i])

    def check_secret_key_equal(self, sk, algorithm_name, key_size, key_bytes):
        self.assertEqual(sk.algorithm, algorithm_name)
        self.assertEqual(sk.key_size, key_size)
        self.assertEqual(sk.key, key_bytes)

    def _test_create_and_load_keystore(self, store_type, store_pw, entry_list, entry_passwords=None):
        """
        Helper function; creates a store of the given type, inserts the given set of entries, and forwards it to save_reload_and_verify_identical
        to verify that it can be successfully saved out to disk and read back out again by both pyjks and Java, and that both reloaded versions
        see the same content as was in the original store.
        """
        store = None
        if store_type in ["jks", "jceks"]:
            store = jks.KeyStore.new(store_type, entry_list)
        elif store_type == "bks":
            store = jks.BksKeyStore.new(store_type, entry_list)
        elif store_type == "uber":
            store = jks.UberKeyStore.new(store_type, entry_list)
        else:
            self.fail("Bad store_type")

        self.save_reload_and_verify_identical(store, store_pw, entry_passwords=entry_passwords)

    def save_reload_and_verify_identical(self, store, store_pw, entry_passwords=None):
        """
        Given a store object, saves it out to a file and loads it back in, once with pyjks and once with Java, and verifies that both see
        the same content as in the original store.
        Entries are encrypted (and later decrypted again) using passwords provided in the entry_passwords dict, or the store password otherwise.
        """
        entry_passwords = (entry_passwords or {})
        bytez = store.saves(store_pw, entry_passwords=entry_passwords)

        store2 = store.__class__.loads(bytez, store_pw)
        self.assertEqual(store.store_type, store2.store_type)

        # verify content of store reloaded with pyjks
        self.assertEqual(len(store.entries), len(store2.entries))
        for alias, item1 in store.entries.items():
            item2 = store2.entries[alias]
            item2.decrypt(entry_passwords.get(alias, store_pw))

            if isinstance(item1, jks.PrivateKeyEntry):
                self.check_pkey_and_certs_equal(item1, item2.algorithm_oid, item2.pkey_pkcs8, [c[1] for c in item2.cert_chain])
            elif isinstance(item1, jks.SecretKeyEntry):
                self.check_secret_key_equal(item1, item2.algorithm, len(item2.key)*8, item2.key)
            elif isinstance(item1, jks.TrustedCertEntry):
                self.check_cert_equal(item1, item2.type, item2.cert)
            else:
                self.fail("Unexpected store entry (type %s)" % type(item1))

        # verify content of store reloaded with java
        java_entry_list = None
        with tempfile_path() as path:
            with open(path, "wb") as f:
                f.write(bytez)
            java_entry_list = self.java_store2json(store.store_type, path, store_pw, entry_passwords=entry_passwords)

        self.assertEqual(set(store.entries.keys()), set(e["alias"] for e in java_entry_list))
        java_entries = dict((e["alias"], e) for e in java_entry_list)
        for alias, itemdict2 in java_entries.items():
            item1 = store.entries[alias]
            if isinstance(item1, jks.jks.PrivateKeyEntry):
                name2oid = {
                    "RSA": jks.util.RSA_ENCRYPTION_OID,
                    "DSA": jks.util.DSA_OID
                }
                self.check_pkey_and_certs_equal(item1, name2oid[itemdict2["algorithm"]],
                                                java2bytes(itemdict2["encoded"]), [java2bytes(c["cert_data"]) for c in itemdict2["certs"]])
            elif isinstance(item1, jks.jks.SecretKeyEntry):
                self.check_secret_key_equal(item1, itemdict2["algorithm"], len(java2bytes(itemdict2["encoded"]))*8, java2bytes(itemdict2["encoded"]))
            elif isinstance(item1, jks.jks.TrustedCertEntry):
                self.check_cert_equal(item1, itemdict2["cert_type"], java2bytes(itemdict2["cert_data"]))
            else:
                self.fail("Unexpected store entry (type %s)" % type(item1))

    @classmethod
    def java_store2json(cls, store_type, store_path, store_password, entry_passwords=None):
        """
        Reads a store on disk using a Java keystore dumper utility and returns a dump of its content (as seen by Java) as a JSON data structure.
        """
        if not java_dumper_jar_path: # populated in setUpModule() iff we were able to build the utility's JAR
            raise unittest.SkipTest("org.pyjks.KeystoreDumper Java utility not built; unable to verify saved keystore contents with Java")
        if not os.path.exists(java_dumper_jar_path):
            raise unittest.SkipTest("Java KeystoreDumper utility was built, but its JAR file was not found at expected location '%s'" % (java_dumper_jar_path,))

        # Note: both store/entry passwords and entry aliases may contain arbitrary unicode character, which might not survive
        # the process call intact if you pass them as bare argument (depends on system default encoding, etc.).
        # So we pass them as base64-encoded UTF-8 instead.
        command = ["java", "-cp", java_dumper_jar_path, java_dumper_main_class, store_type, store_path, base64.b64encode(store_password.encode("utf-8"))]

        entry_passwords = (entry_passwords or {})
        for alias, pw in entry_passwords.items():
            command += [base64.b64encode(alias.encode("utf-8")),
                        base64.b64encode(pw.encode("utf-8"))]

        output = subprocess.check_output(command)
        output = output.decode("utf-8", "strict") # KeystoreDumper emits UTF-8 encoded JSON
        xjson = json.loads(output, encoding="utf-8")
        return xjson

class JksAndJceksLoadTests(AbstractTest):
    """
    Test cases that apply to reading either JKS or JCEKS stores.
    """
    def _test_load_empty_store(self, store_type):
        store = jks.KeyStore.load(KS_PATH + "/{0}/empty.{0}".format(store_type), "")
        self.assertEqual(store.store_type, store_type)
        self.assertEqual(len(store.entries), 0)

    def test_load_empty_store(self):
        self._test_load_empty_store("jks")
        self._test_load_empty_store("jceks")

    def _test_bad_keystore_format(self, store_type):
        magic_bytes = jks.MAGIC_NUMBER_JKS if (store_type == "jks") else jks.MAGIC_NUMBER_JCEKS

        self.assertRaises(jks.util.BadKeystoreFormatException,          jks.KeyStore.loads, b"\x00\x00\x00\x00", "") # bad magic bytes
        self.assertRaises(jks.util.BadKeystoreFormatException,          jks.KeyStore.loads, magic_bytes + b"\x00", "") # insufficient store version bytes
        self.assertRaises(jks.util.UnsupportedKeystoreVersionException, jks.KeyStore.loads, magic_bytes + b"\x00\x00\x00\x00", "") # unknown store version
        self.assertRaises(jks.util.KeystoreSignatureException,          jks.KeyStore.loads, magic_bytes + b"\x00\x00\x00\x02\x00\x00\x00\x00" + b"\x00"*20, "") # bad signature
        self.assertRaises(jks.util.BadKeystoreFormatException,          jks.KeyStore.loads, magic_bytes + b"\x00\x00\x00\x02\x00\x00\x00\x00" + b"\x00"*19, "") # insufficient signature bytes

        self.assertRaises(jks.util.BadKeystoreFormatException, jks.KeyStore.loads,
            magic_bytes + b"\x00\x00\x00\x02\x00\x00\x00\x01" + \
            b"\x00\x00\x00\x02" b"\x00\x05" b"\xFF\xFF\xFF\xFF\xFF", "") # bad alias UTF-8 data

        self.assertRaises(jks.util.BadKeystoreFormatException, jks.KeyStore.loads,
            magic_bytes + b"\x00\x00\x00\x02\x00\x00\x00\x01" + \
            b"\xFF\xFF\xFF\xFF" b"\x00\x05" b"\x41\x41\x41\x41\x41" + jks.util.b8.pack(int(time.time()*1000)), "") # unknown entry type

        self.assertRaises(jks.util.BadKeystoreFormatException, jks.KeyStore.loads,
            jks.MAGIC_NUMBER_JKS + b"\x00\x00\x00\x02\x00\x00\x00\x01" + \
            b"\x00\x00\x00\x03" b"\x00\x05" b"\x41\x41\x41\x41\x41" + jks.util.b8.pack(int(time.time()*1000)), "") # JCEKS entry type in JKS store

    def test_bad_keystore_format(self):
        self._test_bad_keystore_format("jks")
        self._test_bad_keystore_format("jceks")

    def _test_trailing_data(self, store_type):
        """Issue #21 on github; Portecle is able to load keystores with trailing data after the hash, so we should be as well."""
        store_bytes = None
        with open(KS_PATH + "/{0}/RSA1024.{0}".format(store_type), "rb") as f:
            store_bytes = f.read()
        store = jks.KeyStore.loads(store_bytes + b"\x00"*1,    "12345678")
        store = jks.KeyStore.loads(store_bytes + b"\x00"*1000, "12345678")

    def test_trailing_data(self):
        self._test_trailing_data("jks")
        self._test_trailing_data("jceks")

    def _test_rsa_1024(self, store_type):
        store = jks.KeyStore.load(KS_PATH + "/{0}/RSA1024.{0}".format(store_type), "12345678")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, store_type)
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.RSA1024.private_key, expected.RSA1024.certs)

    def test_rsa_1024(self):
        self._test_rsa_1024("jks")
        self._test_rsa_1024("jceks")

    def _test_rsa_2048_3certs(self, store_type):
        store = jks.KeyStore.load(KS_PATH + "/{0}/RSA2048_3certs.{0}".format(store_type), "12345678")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, store_type)
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.RSA2048_3certs.private_key, expected.RSA2048_3certs.certs)

    def test_rsa_2048_3certs(self):
        self._test_rsa_2048_3certs("jks")
        self._test_rsa_2048_3certs("jceks")

    def _test_dsa_2048(self, store_type):
        store = jks.KeyStore.load(KS_PATH + "/{0}/DSA2048.{0}".format(store_type), "12345678")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, store_type)
        self.check_pkey_and_certs_equal(pk, jks.util.DSA_OID, expected.DSA2048.private_key, expected.DSA2048.certs)

    def test_dsa_2048(self):
        self._test_dsa_2048("jks")
        self._test_dsa_2048("jceks")

    def _test_certs(self, store_type):
        store = jks.KeyStore.load(KS_PATH + "/{0}/3certs.{0}".format(store_type), "12345678")
        self.assertEqual(store.store_type, store_type)

        cert1 = self.find_cert(store, "cert1")
        cert2 = self.find_cert(store, "cert2")
        cert3 = self.find_cert(store, "cert3")
        self.assertEqual(cert1.cert, expected.RSA2048_3certs.certs[0])
        self.assertEqual(cert2.cert, expected.RSA2048_3certs.certs[1])
        self.assertEqual(cert3.cert, expected.RSA2048_3certs.certs[2])

    def test_certs(self):
        self._test_certs("jks")
        self._test_certs("jceks")

    def _test_custom_entry_passwords(self, store_type):
        store = jks.KeyStore.load(KS_PATH + "/{0}/custom_entry_passwords.{0}".format(store_type), "store_password")
        self.assertEqual(store.store_type, store_type)
        self.assertEqual(len(store.entries), 3 if store_type == "jceks" else 2)
        self.assertEqual(len(store.certs), 1)
        self.assertEqual(len(store.private_keys), 1)
        self.assertEqual(len(store.secret_keys), 1 if store_type == "jceks" else 0)

        pk = self.find_private_key(store, "private")
        self.assertRaises(jks.DecryptionFailureException, pk.decrypt, "wrong_password")
        self.assertTrue(not pk.is_decrypted())
        pk.decrypt("private_password")
        self.assertTrue(pk.is_decrypted())
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.custom_entry_passwords.private_key, expected.custom_entry_passwords.certs)

        cert = self.find_cert(store, "cert")
        self.assertEqual(cert.cert, expected.custom_entry_passwords.certs[0])

        # JCEKS version of this store additionally contains a SecretKey
        if store_type == "jceks":
            sk = self.find_secret_key(store, "secret")
            self.assertRaises(jks.DecryptionFailureException, sk.decrypt, "wrong_password")
            sk.decrypt("secret_password")
            self.assertTrue(sk.is_decrypted())
            self.assertEqual(sk.key, b"\x3f\x68\x05\x04\xc6\x6c\xc2\x5a\xae\x65\xd0\xfa\x49\xc5\x26\xec")
            self.assertEqual(sk.algorithm, "AES")
            self.assertEqual(sk.key_size, 128)

    def test_custom_entry_passwords(self):
        self._test_custom_entry_passwords("jks")
        self._test_custom_entry_passwords("jceks")

    def _test_duplicate_aliases(self, store_type):
        self.assertRaises(jks.DuplicateAliasException, jks.KeyStore.load, KS_PATH + "/{0}/duplicate_aliases.{0}".format(store_type), "12345678")

    def test_duplicate_aliases(self):
        self._test_duplicate_aliases("jks")
        self._test_duplicate_aliases("jceks")

    def _test_unicode_passwords(self, store_type):
        fancy_store_password = u"\u0000\u0041\u00b3\u05e4\u080a\ud7fb\ue000\uffee\U000100a6"
        fancy_entry_password = u"\U000100a6\uffee\ue000\ud7fb\u080a\u05e4\u00b3\u0041\u0000"
        #int[] codePoints = new int[]{
        #    0x00000000, // NUL
        #    0x00000041, // A                                   range 0x0000 - 0x007F
        #    0x000000B3, // superscript three                   range 0x0080 - 0x07FF
        #    0x000005E4, // hebrew letter PE                    range 0x0080 - 0x07FF
        #    0x0000080A, // samaritan letter kaaf               range 0x0800 - 0xD800
        #    0x0000D7FB, // hangul jongseong phieuph-thieuth    range 0x0800 - 0xD800
        #    0x0000E000, // private use area                    range 0xE000 - 0xFFFF
        #    0x0000FFEE, // halfwidth white circle              range 0xE000 - 0xFFFF
        #    0x000100A6, // linear b ideogram b158              range 0x10000 - 0x10FFFF
        #};
        store = jks.KeyStore.load(KS_PATH + "/{0}/unicode_passwords.{0}".format(store_type), fancy_store_password, try_decrypt_keys=False)
        self.assertEqual(store.store_type, store_type)

        pk = self.find_private_key(store, "mykey")
        self.assertTrue(not pk.is_decrypted())
        pk.decrypt(fancy_entry_password if store_type == "jks" else "12345678") # JCEKS keystores require ASCII-only entry passwords
        self.assertTrue(pk.is_decrypted())
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.unicode_passwords.private_key, expected.unicode_passwords.certs)

    def test_unicode_passwords(self):
        self._test_unicode_passwords("jks")
        self._test_unicode_passwords("jceks")

    def _test_unicode_aliases(self, store_type):
        fancy_alias_1 = u"\u0000\u0061\u00b3\u05e4\u080a\ud7fb\ue000\uffee\U000100a6"
        fancy_alias_2 = u"\U000100a6\uffee\ue000\ud7fb\u080a\u05e4\u00b3\u0061\u0000"

        store = jks.KeyStore.load(KS_PATH + "/{0}/unicode_aliases.{0}".format(store_type), "12345678")
        self.assertEqual(store.store_type, store_type)

        cert1 = self.find_cert(store, fancy_alias_1)
        cert2 = self.find_cert(store, fancy_alias_2)

        self.check_cert_equal(cert1, "X.509", expected.unicode_aliases.certs[0])
        self.check_cert_equal(cert2, "X.509", expected.unicode_aliases.certs[1])

    def test_unicode_aliases(self):
        self._test_unicode_aliases("jks")
        self._test_unicode_aliases("jceks")

    def test_jceks_bad_private_key_decrypt(self):
        # In JCEKS stores, the key protection scheme is password-based encryption with PKCS#5/7 padding, so any wrong password has a 1/256
        # chance of producing a 0x01 byte as the last byte and passing the padding check but producing garbage plaintext.
        # Make sure we can tell when that happens.

        # Here's a dummy PKCS#8 structure, and its encrypted form under chosen parameters password, salt and iteration count:
        pkcs8_plaintext = b"\x30\x15\x02\x01\x00\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x04\x01\xff"

        correct_password = "private_password"
        salt = b"\x74\x9f\xf1\x03\x42\x63\x28\x1c"
        iteration_count = 1677
        ciphertext = b"\xc5\x3d\x8e\x3d\x0f\x64\x8f\xbb\xb0\xe9\x10\x67\xe2\xdd\xbf\xb2\xc3\xcf\x44\x4b\x46\x5f\x57\x1f"

        self.assertEqual(pkcs8_plaintext, jks.sun_crypto.jce_pbe_decrypt(ciphertext, correct_password, salt, iteration_count))

        # Here's another password such that decrypting the ciphertext (with the same salt and iterationcount) produces plaintext ending in \x01 (prior to stripping padding):
        wrong_password = "{bpJs}+?"

        # Now check that creating a PrivateKeyEntry from this encrypted form and trying to decrypt it with the wrong password
        # notices that the resulting plaintext is garbage:
        pbe_params = jks.rfc2898.PBEParameter()
        pbe_params.setComponentByName('salt', salt)
        pbe_params.setComponentByName('iterationCount', iteration_count)
        a = rfc2459.AlgorithmIdentifier()
        a.setComponentByName('algorithm', jks.sun_crypto.SUN_JCE_ALGO_ID)
        a.setComponentByName('parameters', encoder.encode(pbe_params))
        epki = jks.rfc5208.EncryptedPrivateKeyInfo()
        epki.setComponentByName('encryptionAlgorithm', a)
        epki.setComponentByName('encryptedData', ciphertext)
        epki_bytes = encoder.encode(epki)

        pk = jks.PrivateKeyEntry(encrypted=epki_bytes, store_type="jceks")
        self.assertRaises(DecryptionFailureException, pk.decrypt, wrong_password)
        pk.decrypt(correct_password) # shouldn't throw
        self.assertEqual(pk.pkey_pkcs8, pkcs8_plaintext)

    def test_jceks_bad_secret_key_decrypt(self):
        # here's a valid serialized java.security.KeyRep object (contains an "AES" key of value "\xee\xee\xee\xee\xee\xee\xee\xee")
        key = b"\xee"*8
        keyrep_bytes = b"\xac\xed\x00\x05\x73\x72\x00\x14\x6a\x61\x76\x61\x2e\x73\x65\x63\x75\x72\x69\x74\x79\x2e\x4b\x65\x79\x52\x65\x70\xbd\xf9\x4f\xb3" + \
                       b"\x88\x9a\xa5\x43\x02\x00\x04\x4c\x00\x09\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67" + \
                       b"\x2f\x53\x74\x72\x69\x6e\x67\x3b\x5b\x00\x07\x65\x6e\x63\x6f\x64\x65\x64\x74\x00\x02\x5b\x42\x4c\x00\x06\x66\x6f\x72\x6d\x61\x74" + \
                       b"\x71\x00\x7e\x00\x01\x4c\x00\x04\x74\x79\x70\x65\x74\x00\x1b\x4c\x6a\x61\x76\x61\x2f\x73\x65\x63\x75\x72\x69\x74\x79\x2f\x4b\x65" + \
                       b"\x79\x52\x65\x70\x24\x54\x79\x70\x65\x3b\x78\x70\x74\x00\x03\x41\x45\x53\x75\x72\x00\x02\x5b\x42\xac\xf3\x17\xf8\x06\x08\x54\xe0" + \
                       b"\x02\x00\x00\x78\x70\x00\x00\x00\x08" + key +                     b"\x74\x00\x03\x52\x41\x57\x7e\x72\x00\x19\x6a\x61\x76\x61\x2e" + \
                       b"\x73\x65\x63\x75\x72\x69\x74\x79\x2e\x4b\x65\x79\x52\x65\x70\x24\x54\x79\x70\x65\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x78" + \
                       b"\x72\x00\x0e\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x45\x6e\x75\x6d\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x78\x70\x74\x00" + \
                       b"\x06\x53\x45\x43\x52\x45\x54"
        self.assertEqual(keyrep_bytes + b"\x01", add_pkcs7_padding(keyrep_bytes, 8))

        # here's that serialized object encrypted with specific choices for the JCEKS key protection algorithm
        pw1 = "secret_password"
        salt = b"\x38\xfa\x0f\xab\x04\x02\xe0\x49"
        iteration_count = 1962
        ciphertext = b"\x15\x04\x2f\xfc\x62\xe1\x0a\xca\xa1\x13\xa5\x68\xb7\xd7\xce\x8f\x1f\x14\xe1\x73\x7a\x56\x73\x1b\xb4\x62\x30\x3f\x13\x19\x52\xbe" + \
                     b"\x7a\xba\x2a\xf7\x92\x3b\x18\x36\x48\x03\x3e\x60\xe6\x1c\x58\x9e\x0b\xb3\x5b\x09\xb9\xde\x51\x21\xcd\xa2\x3d\xeb\xb5\xc4\xf1\xee" + \
                     b"\xa1\xe0\x6a\xe6\x28\x87\x0a\xdb\xfd\x7b\xca\x4b\x74\xab\x77\xe3\x04\xd6\xe4\x3c\x19\x96\x2d\xf1\xb4\x25\xf4\xef\x64\xb5\x3a\xa6" + \
                     b"\xa4\xc1\x2c\x20\x1d\x5a\x5e\xf4\x6b\xba\x81\x4a\x69\xcf\xb2\xc4\xba\x4b\x93\x09\xb8\xbb\xbd\x00\xee\x59\xc7\xea\x29\xd5\x49\x36" + \
                     b"\x7b\x1c\x14\xd1\x46\xcc\x7b\x7a\xe2\x05\x7a\x64\x8d\x41\xd6\x24\xa5\x30\xb0\xfb\xdd\x78\xb3\xf2\x6f\xee\xb1\x7e\x8a\x16\x82\x83" + \
                     b"\x60\xae\x36\x75\x54\xef\x8f\x4b\x36\x6e\x96\xf7\xe0\x55\xb7\x4e\x02\x14\xd8\xda\x3f\x26\x77\x2d\xf2\xec\x7a\xf0\x62\x04\xa7\x24" + \
                     b"\xd7\x23\xc5\x26\xfd\x0e\xe8\xad\x6d\x01\xed\xea\xb0\xbd\x20\xeb\x8b\x98\x22\x68\x7d\x75\x9b\xc0\x4c\xcf\xc8\x67\xa7\xe5\xd3\xe1" + \
                     b"\xc9\x5f\xc6\x21\xef\xdb\xb8\x0d\xb6\xe1\x66\xbc\x32\xfa\xaf\x44\x10\xad\xc4\xe1\x4f\xa5\x3f\xc9\x06\x68\x86\x5d\xb8\x70\xc2\x05" + \
                     b"\xab\x87\x7d\x94\xaf\x34\x52\x97"
        self.assertEqual(keyrep_bytes, jks.sun_crypto.jce_pbe_decrypt(ciphertext, pw1, salt, iteration_count)) # just to show that the ciphertext is correct
        self.assertEqual(len(ciphertext), len(keyrep_bytes)+1)

        # now here's another password PW2 such that decrypting the ciphertext (with the same salt and iterationcount) produces plaintext ending in \x01 (prior to stripping padding)
        pw2 = "k5#<Myvg"

        # now verify that if we insert this encrypted secret key into a JCEKS keystore, and try to decrypt it with this second password,
        # that the store notices that the resulting plaintext after padding stripping is garbage
        params = jks.rfc2898.PBEParameter()
        params.setComponentByName('salt', salt)
        params.setComponentByName('iterationCount', iteration_count)
        params = encoder.encode(params)

        sobj = jks.SecretKeyEntry._java_SealedObjectForKeyProtector(ciphertext, params, "PBEWithMD5AndTripleDES", "PBEWithMD5AndTripleDES")
        sk = jks.jks.SecretKeyEntry(sealed_obj=sobj, store_type="jceks")
        self.assertRaises(DecryptionFailureException, sk.decrypt, pw2)
        sk.decrypt(pw1) # should not throw
        self.assertEqual(sk.key, key)

class JceSecretKeyLoadTests(AbstractTest):
    """
    Tests specifically involving reading SecretKeys in JCEKS keystores
    """
    def _test_load_secret_key(self, store_path, store_pw, alias, expected_alg, expected_key):
        store = jks.KeyStore.load(KS_PATH + store_path, store_pw)
        sk = self.find_secret_key(store, alias)
        self.assertEqual(store.store_type, "jceks")
        self.check_secret_key_equal(sk, expected_alg, len(expected_key)*8, expected_key)

    def test_des_secret_key(self):
        self._test_load_secret_key("/jceks/DES.jceks", "12345678", "mykey", "DES", b"\x4c\xf2\xfe\x91\x5d\x08\x2a\x43")
    def test_desede_secret_key(self):
        self._test_load_secret_key("/jceks/DESede.jceks", "12345678", "mykey", "DESede", b"\x67\x5e\x52\x45\xe9\x67\x3b\x4c\x8f\xc1\x94\xce\xec\x43\x3b\x31\x8c\x45\xc2\xe0\x67\x5e\x52\x45")
    def test_aes128_secret_key(self):
        self._test_load_secret_key("/jceks/AES128.jceks", "12345678", "mykey", "AES", b"\x66\x6e\x02\x21\xcc\x44\xc1\xfc\x4a\xab\xf4\x58\xf9\xdf\xdd\x3c")
    def test_aes256_secret_key(self):
        self._test_load_secret_key("/jceks/AES256.jceks", "12345678", "mykey", "AES", b"\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f\x68\x77\x12\xfd\xe4\xbe\x52\xe9\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f")
    def test_pbkdf2_hmac_sha1(self):
        self._test_load_secret_key("/jceks/PBKDF2WithHmacSHA1.jceks", "12345678", "mykey", "PBKDF2WithHmacSHA1", b"\x57\x95\x36\xd9\xa2\x7f\x7e\x31\x4e\xf4\xe3\xff\xa5\x76\x26\xef\xe6\x70\xe8\xf4\xd2\x96\xcd\x31\xba\x1a\x82\x7d\x9a\x3b\x1e\xe1")

    def test_unknown_type_of_sealed_object(self):
        """Verify that an exception is raised when encountering a (serialized) Java object inside a SecretKey entry that is not of type javax.crypto.SealedObject"""
        self.assertRaises(jks.UnexpectedJavaTypeException, lambda: \
            jks.KeyStore.load(KS_PATH + "/jceks/unknown_type_of_sealed_object.jceks", "12345678"))

    def test_unknown_type_inside_sealed_object(self):
        """Verify that an exception is raised when encountering a (serialized) Java object inside of a SealedObject in a SecretKey entry (after decryption) that is not of a recognized/supported type"""
        self.assertRaises(jks.UnexpectedJavaTypeException, lambda: \
            jks.KeyStore.load(KS_PATH + "/jceks/unknown_type_inside_sealed_object.jceks", "12345678"))

    def test_unknown_sealed_object_sealAlg(self):
        self.assertRaises(jks.UnexpectedAlgorithmException, lambda: \
            jks.KeyStore.load(KS_PATH + "/jceks/unknown_sealed_object_sealAlg.jceks", "12345678"))

class JksAndJceksSaveTests(AbstractTest):
    """
    Test cases that apply to writing either JKS or JCEKS stores.
    """
    def _test_jks_nodecrypt_roundtrip_identical(self, store_path, store_pw):
        """
        Specific test for JKS keystores:
          If you load a JKS keystore, don't decrypt any of the keys, save it back out with the same store password, and you also happen to get the entries
          written out in the same order as the original, then you should get byte-identical output.
        """
        with open(KS_PATH + store_path, 'rb') as file:
            keystore_bytes = file.read()
        store = jks.KeyStore.loads(keystore_bytes, store_pw, try_decrypt_keys=False)
        resaved = store.saves(store_pw)
        self.assertEqual(keystore_bytes, resaved)

    def test_jks_nodecrypt_roundtrip_rsa1024(self):
        self._test_jks_nodecrypt_roundtrip_identical("/jks/RSA1024.jks", "12345678")
    def test_jks_nodecrypt_roundtrip_rsa2048(self):
        self._test_jks_nodecrypt_roundtrip_identical("/jks/RSA2048_3certs.jks", "12345678")
    def test_jks_nodecrypt_roundtrip_dsa(self):
        self._test_jks_nodecrypt_roundtrip_identical("/jks/DSA2048.jks", "12345678")
    def test_jks_nodecrypt_roundtrip_non_ascii_password(self):
        self._test_jks_nodecrypt_roundtrip_identical("/jks/unicode_passwords.jks", u"\u0000\u0041\u00b3\u05e4\u080a\ud7fb\ue000\uffee\U000100a6")

    def test_create_and_load_empty_keystore(self):
        self._test_create_and_load_keystore("jks",   "12345678", [])
        self._test_create_and_load_keystore("jceks", "12345678", [])

    def test_create_and_load_keystore_unicode_passwords(self):
        fancy_password = u"\u0000\u0041\u00b3\u05e4\u080a\ud7fb\ue000\uffee\U000100a6"
        pk = jks.PrivateKeyEntry.new("mykey", expected.unicode_passwords.certs, expected.unicode_passwords.private_key)
        items = [pk]

        #self._test_create_and_load_keystore("jks", fancy_password, [pk])
        #self.assertRaises(ValueError, self._test_create_and_load_keystore, "jceks", fancy_password, [pk]) # JCEKS stores require ASCII passwords, so this should fail

        # Note: JCEKS stores require that entry passwords are ASCII-only (the store password can still be non-ASCII).
        # JKS stores have no such restriction.
        self._test_create_and_load_keystore("jks",   fancy_password, items)
        self.assertRaises(IllegalPasswordCharactersException, self._test_create_and_load_keystore, "jceks", fancy_password, items) # private key will get auto-encrypted with the store password
        self.assertRaises(IllegalPasswordCharactersException, self._test_create_and_load_keystore, "jceks", "12345678", items, entry_passwords={"mykey": fancy_password}) # show that the issue is with the key's password ...
        self._test_create_and_load_keystore("jceks", fancy_password, items, entry_passwords={"mykey": "12345678"}) # ... not the store password.

    def test_create_and_load_unicode_aliases(self):
        fancy_alias = u"\xe6\xe6\xe6\xf8\xf8\xf8\xe5\xe5\xf8\xe6"
        pk = jks.PrivateKeyEntry.new(fancy_alias, expected.RSA1024.certs, expected.RSA1024.private_key)

        self._test_create_and_load_keystore("jks",   "12345678", [pk])
        self._test_create_and_load_keystore("jceks", "12345678", [pk])

    def test_create_and_load_oversized_alias(self):
        oversized_alias = "a"*(0xFFFF+1)
        pk = jks.PrivateKeyEntry.new(oversized_alias, expected.RSA2048_3certs.certs, expected.RSA2048_3certs.private_key)

        self.assertRaises(jks.util.BadDataLengthException, self._test_create_and_load_keystore, "jks",   "12345678", [pk])
        self.assertRaises(jks.util.BadDataLengthException, self._test_create_and_load_keystore, "jceks", "12345678", [pk])

    def test_create_and_load_custom_entry_passwords(self):
        pk = jks.PrivateKeyEntry.new("mykey", expected.custom_entry_passwords.certs, expected.custom_entry_passwords.private_key)
        entry_passwords = {pk.alias: "private_password"}

        self._test_create_and_load_keystore("jks",   "store_password", [pk], entry_passwords=entry_passwords)
        self._test_create_and_load_keystore("jceks", "store_password", [pk], entry_passwords=entry_passwords)

    def test_create_and_load_keystore_pkcs8_rsa(self):
        pk = jks.PrivateKeyEntry.new('mykey', expected.RSA2048_3certs.certs, expected.RSA2048_3certs.private_key)
        self._test_create_and_load_keystore("jks",   "12345678", [pk])
        self._test_create_and_load_keystore("jceks", "12345678", [pk])

    def test_create_and_load_keystore_pkcs8_dsa(self):
        pk = jks.PrivateKeyEntry.new('mykey', expected.DSA2048.certs, expected.DSA2048.private_key)
        self._test_create_and_load_keystore("jks",   "12345678", [pk])
        self._test_create_and_load_keystore("jceks", "12345678", [pk])

    def test_create_and_load_keystore_raw_rsa(self):
        # TODO: this is an orthogonal issue to keystore saving/reloading, make this its own test for the PrivateKeyEntry constructor
        pk = jks.PrivateKeyEntry.new('mykey', expected.RSA2048_3certs.certs, expected.RSA2048_3certs.raw_private_key, key_format='rsa_raw')
        self._test_create_and_load_keystore("jks",   "12345678", [pk])
        self._test_create_and_load_keystore("jceks", "12345678", [pk])

    def test_create_and_load_keystore_trusted_certs(self):
        cert1 = jks.TrustedCertEntry.new("cert1", expected.RSA2048_3certs.certs[0])
        cert2 = jks.TrustedCertEntry.new("cert2", expected.RSA2048_3certs.certs[1])
        cert3 = jks.TrustedCertEntry.new("cert3", expected.RSA2048_3certs.certs[2])
        self._test_create_and_load_keystore("jks",   "12345678", [cert1, cert2, cert3])
        self._test_create_and_load_keystore("jceks", "12345678", [cert1, cert2, cert3])

    def test_create_and_load_keystore_both_trusted_and_private(self):
        pk = jks.PrivateKeyEntry.new('mykey', expected.RSA2048_3certs.certs, expected.RSA2048_3certs.raw_private_key, key_format='rsa_raw')
        cert1 = jks.TrustedCertEntry.new("cert1", expected.RSA2048_3certs.certs[0])
        cert2 = jks.TrustedCertEntry.new("cert2", expected.RSA2048_3certs.certs[1])
        cert3 = jks.TrustedCertEntry.new("cert3", expected.RSA2048_3certs.certs[2])

        self._test_create_and_load_keystore("jks",   "12345678", [pk, cert1, cert2, cert3])
        self._test_create_and_load_keystore("jceks", "12345678", [pk, cert1, cert2, cert3])

    def test_new_keystore_duplicate_alias(self):
        cert1 = jks.TrustedCertEntry.new('cert1', expected.RSA2048_3certs.certs[0])
        cert2 = jks.TrustedCertEntry.new('cert1', expected.RSA2048_3certs.certs[1])
        self.assertRaises(jks.util.DuplicateAliasException, jks.KeyStore.new, 'jks', [cert1, cert2])

    def test_save_invalid_keystore_format(self):
        self.assertRaises(jks.util.UnsupportedKeystoreTypeException, jks.KeyStore.new, 'invalid', [])

    def test_save_invalid_keystore_entry(self):
        self.assertRaises(jks.util.UnsupportedKeystoreEntryTypeException, jks.KeyStore.new, 'jks', ['string'])

    def test_create_unknown_key_format(self):
        self.assertRaises(jks.util.UnsupportedKeyFormatException, jks.PrivateKeyEntry.new, 'alias','cert', 'key', 'ecdsa')

class JceSecretKeySaveTests(AbstractTest):
    def test_des_secret_key(self):
        self._test_create_and_load_keystore("jceks", "12345678", [jks.SecretKeyEntry.new("mykey", "DES", b"\x4c\xf2\xfe\x91\x5d\x08\x2a\x43")])
    def test_desede_secret_key2(self):
        self._test_create_and_load_keystore("jceks", "12345678", [jks.SecretKeyEntry.new("mykey", "DESede", b"\x67\x5e\x52\x45\xe9\x67\x3b\x4c\x8f\xc1\x94\xce\xec\x43\x3b\x31\x8c\x45\xc2\xe0\x67\x5e\x52\x45")])
    def test_aes128_secret_key(self):
        self._test_create_and_load_keystore("jceks", "12345678", [jks.SecretKeyEntry.new("mykey", "AES", b"\x66\x6e\x02\x21\xcc\x44\xc1\xfc\x4a\xab\xf4\x58\xf9\xdf\xdd\x3c")])
    def test_aes256_secret_key(self):
        self._test_create_and_load_keystore("jceks", "12345678", [jks.SecretKeyEntry.new("mykey", "AES", b"\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f\x68\x77\x12\xfd\xe4\xbe\x52\xe9\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f")])
    def test_pbkdf2_hmac_sha1(self):
        self._test_create_and_load_keystore("jceks", "12345678", [jks.SecretKeyEntry.new("mykey", "PBKDF2WithHmacSHA1", b"\x57\x95\x36\xd9\xa2\x7f\x7e\x31\x4e\xf4\xe3\xff\xa5\x76\x26\xef\xe6\x70\xe8\xf4\xd2\x96\xcd\x31\xba\x1a\x82\x7d\x9a\x3b\x1e\xe1")])

    def test_save_jks_keystore_with_secret_key(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/AES128.jceks", "12345678")
        store.store_type = 'jks' # changing it to a jks keystore
        self.assertRaises(jks.util.UnsupportedKeystoreEntryTypeException, store.saves, '12345678')

    def test_create_jks_keystore_with_secret_key(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/AES128.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertRaises(jks.util.UnsupportedKeystoreEntryTypeException, jks.KeyStore.new, 'jks', [sk])

class BksOnlyTests(AbstractTest):
    def check_bks_entry(self, entry, store_type):
        """Checks that apply to BKS entries of any type"""
        self.assertEqual(entry.store_type, store_type)
        self.assertTrue(entry.is_decrypted())
        self.assertTrue(isinstance(entry.alias, py23basestring))
        self.assertTrue(isinstance(entry.timestamp, (int, long)))
        self.assertTrue(isinstance(entry.cert_chain, list))
        self.assertTrue(all(isinstance(c, jks.bks.BksTrustedCertEntry) for c in entry.cert_chain))

    def check_cert_entry(self, entry, store_type):
        self.check_bks_entry(entry, store_type)
        self.assertTrue(entry.is_decrypted())
        self.assertTrue(isinstance(entry.cert, bytes))
        self.assertTrue(isinstance(entry.type, py23basestring))
        self.assertTrue(entry.is_decrypted())

    def check_sealed_key_entry(self, entry, store_type):
        self.check_bks_entry(entry, store_type)
        self.assertTrue(isinstance(entry, jks.bks.BksSealedKeyEntry))
        if entry.is_decrypted():
            # all attributes of the nested entry should also be directly accessible through the parent sealed entry,
            # so run the same check twice with the two different objects
            self.check_plain_key_entry(entry.nested, store_type)
            self.check_plain_key_entry(entry, store_type, check_type=False)

    def check_secret_key_entry(self, entry, store_type):
        self.check_bks_entry(entry, store_type)
        self.assertTrue(entry.is_decrypted())
        self.assertTrue(isinstance(entry, jks.bks.BksSecretKeyEntry))
        self.assertTrue(isinstance(entry.key, bytes))

    def check_plain_key_entry(self, key_entry, store_type, check_type=True):
        self.check_bks_entry(key_entry, store_type)
        if check_type:
            self.assertTrue(isinstance(key_entry, jks.bks.BksKeyEntry))
        self.assertTrue(isinstance(key_entry.format, py23basestring))
        self.assertTrue(isinstance(key_entry.algorithm, py23basestring))
        self.assertTrue(isinstance(key_entry.encoded, bytes))
        self.assertTrue(key_entry.is_decrypted())

        if key_entry.type == jks.bks.BksKeyEntry.KEY_TYPE_PRIVATE:
            self.assertTrue(isinstance(key_entry.pkey_pkcs8, bytes))
            self.assertTrue(isinstance(key_entry.pkey, bytes))
            self.assertTrue(isinstance(key_entry.algorithm_oid, tuple))

        elif key_entry.type == jks.bks.BksKeyEntry.KEY_TYPE_PUBLIC:
            self.assertTrue(isinstance(key_entry.public_key_info, bytes))
            self.assertTrue(isinstance(key_entry.public_key, bytes))
            self.assertTrue(isinstance(key_entry.algorithm_oid, tuple))

        elif key_entry.type == jks.bks.BksKeyEntry.KEY_TYPE_SECRET:
            self.assertTrue(isinstance(key_entry.key, bytes))

        else:
            self.fail("No such key type: %s" % repr(key_entry.type))

    # TODO: code duplication with JKS' check_pkey_and_certs_equal; only difference is that in JKS entries
    # the cert_chain is stored as a tuple instead of a TrustedCertEntry object.
    # consider changing that so this logic can be reused
    def check_pkey_and_certs_equal(self, pk, algorithm_oid, pkey_pkcs8, certs):
        self.assertEqual(pk.algorithm_oid, algorithm_oid)
        self.assertEqual(pk.pkey_pkcs8, pkey_pkcs8)
        self.assertEqual(len(pk.cert_chain), len(certs))
        for i in range(len(certs)):
            self.assertEqual(pk.cert_chain[i].cert, certs[i])

    # ----------------------------------------------

    def test_bad_bks_keystore_format(self):
        self.assertRaises(jks.util.BadKeystoreFormatException, jks.bks.BksKeyStore.loads, b"\x00\x00\x00", "") # insufficient store version bytes
        self.assertRaises(jks.util.UnsupportedKeystoreVersionException, jks.bks.BksKeyStore.loads, b"\x00\x00\x00\x00" + b"\x00\x00\x00\x08" + (b"\xFF"*8) + b"\x00\x00\x00\x14" + b"\x00" + (b"\x00"*20), "") # unknown store version
        self.assertRaises(jks.util.KeystoreSignatureException, jks.bks.BksKeyStore.loads, b"\x00\x00\x00\x02" + b"\x00\x00\x00\x08" + (b"\xFF"*8) + b"\x00\x00\x00\x14" + b"\x00" + (b"\x00"*20), "") # bad HMAC
        self.assertRaises(jks.util.BadKeystoreFormatException, jks.bks.BksKeyStore.loads, b"\x00\x00\x00\x02" + b"\x00\x00\x00\x08" + (b"\xFF"*8) + b"\x00\x00\x00\x14" + b"\x00" + (b"\x00"*19), "") # insufficient HMAC bytes

    def test_bad_uber_keystore_format(self):
        self.assertRaises(jks.util.BadKeystoreFormatException, jks.bks.UberKeyStore.loads, b"\x00\x00\x00", "") # insufficient store version bytes
        self.assertRaises(jks.util.UnsupportedKeystoreVersionException, jks.bks.UberKeyStore.loads, b"\x00\x00\x00\x00" + b"\x00\x00\x00\x08" + (b"\xFF"*8) + b"\x00\x00\x00\x14", "") # unknown store version

        password = ""
        salt = b"\xFF"*8
        self.assertRaises(jks.util.KeystoreSignatureException, jks.bks.UberKeyStore.loads,
            b"\x00\x00\x00\x01" + \
            b"\x00\x00\x00\x08" + salt + \
            b"\x00\x00\x00\x14" + \
            jks.rfc7292.encrypt_PBEWithSHAAndTwofishCBC(b"\x00" + b"\00"*20, password, salt, 0x14), password) # empty embedded BKS entries + bad SHA-1 hash of that 0-byte store

        self.assertRaises(jks.util.BadKeystoreFormatException, jks.bks.UberKeyStore.loads,
            b"\x00\x00\x00\x01" + \
            b"\x00\x00\x00\x08" + salt + \
            b"\x00\x00\x00\x14" + \
            jks.rfc7292.encrypt_PBEWithSHAAndTwofishCBC(b"\x00" + b"\00"*10, password, salt, 0x14), password) # insufficient signature bytes

    def test_empty_store_v1(self):
        store = jks.bks.BksKeyStore.load(KS_PATH + "/bks/empty.bksv1", "")
        self.assertEqual(store.version, 1)
    def test_empty_store_v2(self):
        store = jks.bks.BksKeyStore.load(KS_PATH + "/bks/empty.bksv2", "")
        self.assertEqual(store.version, 2)
    def test_empty_store_uber(self):
        store = jks.bks.UberKeyStore.load(KS_PATH + "/uber/empty.uber", "")
        self.assertEqual(store.version, 1)

    def test_christmas_store_v1(self):
        store = jks.bks.BksKeyStore.load(KS_PATH + "/bks/christmas.bksv1", "12345678")
        self.assertEqual(store.version, 1)
        self._test_christmas_store(store, "bks")
    def test_christmas_store_v2(self):
        store = jks.bks.BksKeyStore.load(KS_PATH + "/bks/christmas.bksv2", "12345678")
        self.assertEqual(store.version, 2)
        self._test_christmas_store(store, "bks")
    def test_christmas_store_uber(self):
        store = jks.bks.UberKeyStore.load(KS_PATH + "/uber/christmas.uber", "12345678")
        self.assertEqual(store.version, 1)
        self._test_christmas_store(store, "uber")

    def test_custom_entry_passwords_v1(self):
        store = jks.bks.BksKeyStore.load(KS_PATH + "/bks/custom_entry_passwords.bksv1", "store_password")
        self.assertEqual(store.version, 1)
        self._test_custom_entry_passwords(store, "bks")
    def test_custom_entry_passwords_v2(self):
        store = jks.bks.BksKeyStore.load(KS_PATH + "/bks/custom_entry_passwords.bksv2", "store_password")
        self.assertEqual(store.version, 2)
        self._test_custom_entry_passwords(store, "bks")
    def test_custom_entry_passwords_uber(self):
        store = jks.bks.UberKeyStore.load(KS_PATH + "/uber/custom_entry_passwords.uber", "store_password")
        self.assertEqual(store.version, 1)
        self._test_custom_entry_passwords(store, "uber")

    def _test_christmas_store(self, store, store_type):
        self.assertEqual(store.store_type, store_type)
        self.assertEqual(len(store.entries), 6)
        self.assertEqual(len(store.certs), 1)
        self.assertEqual(len(store.sealed_keys), 3)
        self.assertEqual(len(store.secret_keys), 1)
        self.assertEqual(len(store.plain_keys), 1)

        sealed_public = store.entries["sealed_public_key"]
        self.check_sealed_key_entry(sealed_public, store_type)
        self.assertTrue(sealed_public.is_decrypted())
        self.assertEqual(sealed_public.type, jks.bks.BksKeyEntry.KEY_TYPE_PUBLIC)
        self.assertEqual(sealed_public.algorithm, "RSA")
        self.assertEqual(sealed_public.algorithm_oid, jks.util.RSA_ENCRYPTION_OID)
        self.assertEqual(sealed_public.public_key_info, expected.bks_christmas.public_key)

        sealed_private = store.entries["sealed_private_key"]
        self.check_sealed_key_entry(sealed_private, store_type)
        self.assertEqual(sealed_private.type, jks.bks.BksKeyEntry.KEY_TYPE_PRIVATE)
        self.assertEqual(sealed_private.algorithm, "RSA")
        self.assertTrue(sealed_private.is_decrypted())
        self.check_pkey_and_certs_equal(sealed_private, jks.util.RSA_ENCRYPTION_OID, expected.bks_christmas.private_key, expected.bks_christmas.certs)

        sealed_secret = store.entries["sealed_secret_key"]
        self.check_sealed_key_entry(sealed_secret, store_type)
        self.assertEqual(sealed_secret.type, jks.bks.BksKeyEntry.KEY_TYPE_SECRET)
        self.assertEqual(sealed_secret.algorithm, "AES")
        self.check_secret_key_equal(sealed_secret, "AES", 128, b"\x3f\x68\x05\x04\xc6\x6c\xc2\x5a\xae\x65\xd0\xfa\x49\xc5\x26\xec")

        plain_key = store.entries["plain_key"]
        self.check_plain_key_entry(plain_key, store_type)
        self.assertEqual(plain_key.type, jks.bks.BksKeyEntry.KEY_TYPE_SECRET)
        self.assertEqual(plain_key.algorithm, "DES")
        self.check_secret_key_equal(plain_key, "DES", 64, b"\x4c\xf2\xfe\x91\x5d\x08\x2a\x43")

        cert = store.entries["cert"]
        self.check_cert_entry(cert, store_type)
        self.assertEqual(cert.cert, expected.bks_christmas.certs[0])

        stored_value = store.entries["stored_value"]
        self.check_secret_key_entry(stored_value, store_type)
        self.assertEqual(stored_value.key, b"\x02\x03\x05\x07\x0B\x0D\x11\x13\x17")

    def _test_custom_entry_passwords(self, store, store_type):
        self.assertEqual(store.store_type, store_type)
        self.assertEqual(len(store.entries), 3)
        self.assertEqual(len(store.certs), 0)
        self.assertEqual(len(store.sealed_keys), 3)
        self.assertEqual(len(store.secret_keys), 0)
        self.assertEqual(len(store.plain_keys), 0)

        attrs_non_encrypted = ["alias", "timestamp", "store_type", "cert_chain"]
        attrs_encrypted_common = ["type", "format", "algorithm", "encoded"]
        attrs_encrypted_public  = attrs_encrypted_common + ["public_key_info", "public_key", "algorithm_oid"]
        attrs_encrypted_private = attrs_encrypted_common + ["pkey", "pkey_pkcs8", "algorithm_oid"]
        attrs_encrypted_secret  = attrs_encrypted_common + ["key", "key_size"]

        sealed_public = store.entries["sealed_public_key"]
        self.assertFalse(sealed_public.is_decrypted())
        for a in attrs_encrypted_public: self.assertRaises(jks.util.NotYetDecryptedException, getattr, sealed_public, a)
        for a in attrs_non_encrypted: getattr(sealed_public, a) # shouldn't throw
        self.assertRaises(jks.util.DecryptionFailureException, sealed_public.decrypt, "wrong_password")
        sealed_public.decrypt("public_password")
        self.assertTrue(sealed_public.is_decrypted())
        for a in attrs_encrypted_public: getattr(sealed_public, a) # shouldn't throw
        sealed_public.decrypt("wrong_password") # additional decrypt() calls should do nothing

        sealed_private = store.entries["sealed_private_key"]
        self.assertFalse(sealed_private.is_decrypted())
        for a in attrs_encrypted_private: self.assertRaises(jks.util.NotYetDecryptedException, getattr, sealed_private, a)
        for a in attrs_non_encrypted: getattr(sealed_private, a) # shouldn't throw
        self.assertRaises(jks.util.DecryptionFailureException, sealed_private.decrypt, "wrong_password")
        sealed_private.decrypt("private_password")
        self.assertTrue(sealed_private.is_decrypted())
        for a in attrs_encrypted_private: getattr(sealed_private, a) # shouldn't throw
        sealed_private.decrypt("wrong_password") # additional decrypt() calls should do nothing

        sealed_secret = store.entries["sealed_secret_key"]
        self.assertFalse(sealed_secret.is_decrypted())
        for a in attrs_encrypted_secret: self.assertRaises(jks.util.NotYetDecryptedException, getattr, sealed_secret, a)
        for a in attrs_non_encrypted: getattr(sealed_secret, a) # shouldn't throw
        self.assertRaises(jks.util.DecryptionFailureException, sealed_secret.decrypt, "wrong_password")
        sealed_secret.decrypt("secret_password")
        self.assertTrue(sealed_secret.is_decrypted())
        for a in attrs_encrypted_secret: getattr(sealed_secret, a) # shouldn't throw
        sealed_secret.decrypt("wrong_password") # additional decrypt() calls should do nothing

    def test_trailing_data_v1(self):
        """Issue #21 on github; Portecle is able to load keystores with trailing data after the HMAC signature, so we should be as well."""
        christmas_store_bytes = None
        with open(KS_PATH + "/bks/christmas.bksv1", "rb") as f:
            christmas_store_bytes = f.read()
        store = jks.bks.BksKeyStore.loads(christmas_store_bytes + b"\x00"*1,    "12345678")
        store = jks.bks.BksKeyStore.loads(christmas_store_bytes + b"\x00"*1000, "12345678")
        self._test_christmas_store(store, "bks")

    def test_trailing_data_v2(self):
        """Issue #21 on github; Portecle is able to load keystores with trailing data after the HMAC signature, so we should be as well."""
        christmas_store_bytes = None
        with open(KS_PATH + "/bks/christmas.bksv2", "rb") as f:
            christmas_store_bytes = f.read()
        store = jks.bks.BksKeyStore.loads(christmas_store_bytes + b"\x00"*1,    "12345678")
        store = jks.bks.BksKeyStore.loads(christmas_store_bytes + b"\x00"*1000, "12345678")
        self._test_christmas_store(store, "bks")

    def test_trailing_data_uber(self):
        # Note: trailing data in an UBER keystore should always be a fatal error because there is no way to distinguish
        # the trailing data from the encrypted store blob in advance.
        christmas_store_bytes = None
        with open(KS_PATH + "/uber/christmas.uber", "rb") as f:
            christmas_store_bytes = f.read()
        self.assertRaises(jks.util.DecryptionFailureException, jks.bks.UberKeyStore.loads, christmas_store_bytes + b"\x00"*256, "12345678") # maintain multiple of 16B -> decryption failure
        self.assertRaises(jks.util.BadKeystoreFormatException, jks.bks.UberKeyStore.loads, christmas_store_bytes + b"\x00"*255, "12345678") # break multiple of 16B -> bad format

    def test_type2str(self):
        self.assertEqual(jks.bks.BksKeyEntry.type2str(jks.bks.BksKeyEntry.KEY_TYPE_PUBLIC),  "PUBLIC")
        self.assertEqual(jks.bks.BksKeyEntry.type2str(jks.bks.BksKeyEntry.KEY_TYPE_PRIVATE), "PRIVATE")
        self.assertEqual(jks.bks.BksKeyEntry.type2str(jks.bks.BksKeyEntry.KEY_TYPE_SECRET),  "SECRET")
        self.assertEqual(jks.bks.BksKeyEntry.type2str(-1),  None)


class MiscTests(AbstractTest):
    def test_decode_modified_utf8(self):
        self.assertEqual('', decode_modified_utf8(b""))
        self.assertEqual(u'\U00000000', decode_modified_utf8(b"\xc0\x80"))
        self.assertEqual(u'\U00000001', decode_modified_utf8(b"\x01"))
        self.assertEqual(u'\U0000007F', decode_modified_utf8(b"\x7f"))
        self.assertEqual(u'\U00000080', decode_modified_utf8(b"\xc2\x80"))
        self.assertEqual(u'\U000007FF', decode_modified_utf8(b"\xdf\xbf"))
        self.assertEqual(u'\U00000800', decode_modified_utf8(b"\xe0\xa0\x80"))
        self.assertEqual(u'\U0000D7FF', decode_modified_utf8(b"\xed\x9f\xbf"))
        self.assertEqual(u'\U0000E000', decode_modified_utf8(b"\xee\x80\x80"))
        self.assertEqual(u'\U0000FFFF', decode_modified_utf8(b"\xef\xbf\xbf"))
        self.assertEqual(u'\U00010000', decode_modified_utf8(b"\xed\xa0\x80\xed\xb0\x80"))
        self.assertEqual(u'\U0010FFFF', decode_modified_utf8(b"\xed\xaf\xbf\xed\xbf\xbf"))

        # overlong sequences
        self.assertRaises(Exception, decode_cesu8, b"\xc0\x80") # encoding U+0000 as 0xC080 is a modified UTF-8 thing, not a CESU-8 thing
        self.assertRaises(Exception, decode_modified_utf8, b"\xe0\x80\x80")
        self.assertRaises(Exception, decode_modified_utf8, b"\xf0\x80\x80\x80")
        self.assertRaises(Exception, decode_modified_utf8, b"\xf8\x80\x80\x80\x80")
        self.assertRaises(Exception, decode_modified_utf8, b"\xfc\x80\x80\x80\x80\x80")

        # unexpected continuation bytes
        self.assertRaises(Exception, decode_modified_utf8, b"\x80")
        self.assertRaises(Exception, decode_modified_utf8, b"\x80\x80")
        self.assertRaises(Exception, decode_modified_utf8, b"\x80\x80\x80")

        # truncated continuations
        self.assertRaises(Exception, decode_modified_utf8, b"\xc0\x41")
        self.assertRaises(Exception, decode_modified_utf8, b"\xd0\x41")
        self.assertRaises(Exception, decode_modified_utf8, b"\xe0\x41")
        self.assertRaises(Exception, decode_modified_utf8, b"\xe0\x80\x41")
        self.assertRaises(Exception, decode_modified_utf8, b"\xf0\x41")
        self.assertRaises(Exception, decode_modified_utf8, b"\xf0\x80\x41")
        self.assertRaises(Exception, decode_modified_utf8, b"\xf0\x80\x80\x41")

        # 4-byte UTF-8 sequences are illegal in CESU-8 and modified-UTF-8
        self.assertRaises(Exception, decode_modified_utf8, b"\xf0\x90\x80\x80")

    def test_encode_modified_utf8(self):
        self.assertEqual(encode_modified_utf8(''), b"")
        self.assertEqual(encode_modified_utf8(u'\U00000000'), b"\xc0\x80")
        self.assertEqual(encode_modified_utf8(u'\U00000001'), b"\x01")
        self.assertEqual(encode_modified_utf8(u'\U0000007F'), b"\x7f")
        self.assertEqual(encode_modified_utf8(u'\U00000080'), b"\xc2\x80")
        self.assertEqual(encode_modified_utf8(u'\U000007FF'), b"\xdf\xbf")
        self.assertEqual(encode_modified_utf8(u'\U00000800'), b"\xe0\xa0\x80")
        self.assertEqual(encode_modified_utf8(u'\U0000D7FF'), b"\xed\x9f\xbf")
        self.assertEqual(encode_modified_utf8(u'\U0000E000'), b"\xee\x80\x80")
        self.assertEqual(encode_modified_utf8(u'\U0000FFFF'), b"\xef\xbf\xbf")
        self.assertEqual(encode_modified_utf8(u'\U00010000'), b"\xed\xa0\x80\xed\xb0\x80")
        self.assertEqual(encode_modified_utf8(u'\U0010FFFF'), b"\xed\xaf\xbf\xed\xbf\xbf")
        
        self.assertEqual(encode_cesu8(u'\U00000000'), b"\x00") # encoding U+0000 as 0xC080 is a modified UTF-8 thing, not a CESU-8 thing

    def test_bitstring_to_bytes(self):
        def bs2b(t, _str):
            bits_tuple = tuple(map(int, _str.replace(" ", "")))
            result = jks.util.bitstring_to_bytes(bits_tuple)
            t.assertTrue(isinstance(result, bytes))
            return result

        self.assertEqual(bs2b(self, ""), b"")

        self.assertEqual(bs2b(self, "        0"), b"\x00")
        self.assertEqual(bs2b(self, "        1"), b"\x01")
        self.assertEqual(bs2b(self, "0110 1010"), b"\x6a")
        self.assertEqual(bs2b(self, "1111 1111"), b"\xff")

        self.assertEqual(bs2b(self, "   0 1111 1111"), b"\x00\xff")
        self.assertEqual(bs2b(self, "   1 1111 1111"), b"\x01\xff")

    def test_strip_pkcs5_padding(self):
        self.assertEqual(jks.util.strip_pkcs5_padding(b"\x08\x08\x08\x08\x08\x08\x08\x08"), b"")
        self.assertEqual(jks.util.strip_pkcs5_padding(b"\x01\x07\x07\x07\x07\x07\x07\x07"), b"\x01")
        self.assertEqual(jks.util.strip_pkcs5_padding(b"\x01\x02\x03\x04\x05\x06\x07\x01"), b"\x01\x02\x03\x04\x05\x06\x07")

        self.assertRaises(jks.util.BadPaddingException, jks.util.strip_pkcs5_padding, b"")
        self.assertRaises(jks.util.BadPaddingException, jks.util.strip_pkcs5_padding, b"\x01")
        self.assertRaises(jks.util.BadPaddingException, jks.util.strip_pkcs5_padding, b"\x01\x02\x03\x04\x08\x08")
        self.assertRaises(jks.util.BadPaddingException, jks.util.strip_pkcs5_padding, b"\x07\x07\x07\x07\x07\x07\x07")
        self.assertRaises(jks.util.BadPaddingException, jks.util.strip_pkcs5_padding, b"\x00\x00\x00\x00\x00\x00\x00\x00")

    def test_add_pkcs7_padding(self):
        self.assertEqual(jks.util.add_pkcs7_padding(b"", 8),     b"\x08\x08\x08\x08\x08\x08\x08\x08")
        self.assertEqual(jks.util.add_pkcs7_padding(b"\x01", 8), b"\x01\x07\x07\x07\x07\x07\x07\x07")
        self.assertEqual(jks.util.add_pkcs7_padding(b"\x01\x02\x03\x04\x05\x06\x07", 8), b"\x01\x02\x03\x04\x05\x06\x07\x01")

        self.assertRaises(ValueError, jks.util.add_pkcs7_padding, b"", -8)   # block size too small
        self.assertRaises(ValueError, jks.util.add_pkcs7_padding, b"", 0)    # block size too small
        self.assertRaises(ValueError, jks.util.add_pkcs7_padding, b"", 256)  # block size too large

    def test_sun_jce_pbe_decrypt(self):
        self.assertEqual(b"sample", jks.sun_crypto.jce_pbe_decrypt(b"\xc4\x20\x59\xac\x54\x03\xc7\xbf", "my_password", b"\x01\x02\x03\x04\x05\x06\x07\x08", 42))
        self.assertEqual(b"sample", jks.sun_crypto.jce_pbe_decrypt(b"\xef\x9f\xbd\xc5\x91\x5f\x49\x50", "my_password", b"\x01\x02\x03\x04\x01\x02\x03\x05", 42))
        self.assertEqual(b"sample", jks.sun_crypto.jce_pbe_decrypt(b"\x72\x8f\xd8\xcc\x21\x41\x25\x80", "my_password", b"\x01\x02\x03\x04\x01\x02\x03\x04", 42))
        self.assertRaises(BadDataLengthException, jks.sun_crypto.jce_pbe_decrypt, b"\x00\x00\x00\x00\x00\x00\x00\x00", "my_password", b"\x00", 42)   # salt too short
        self.assertRaises(BadDataLengthException, jks.sun_crypto.jce_pbe_decrypt, b"\x00\x00\x00\x00\x00\x00\x00\x00", "my_password", b"\x00"*9, 42) # salt too long
        self.assertRaises(IllegalPasswordCharactersException, jks.sun_crypto.jce_pbe_decrypt, b"\xc4\x20\x59\xac\x54\x03\xc7\xbf", "my_p\xc3\xa1ssword", b"\x01\x02\x03\x04\x05\x06\x07\x08", 42) # non-ASCII password characters

    def test_pkcs12_key_derivation(self):
        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_MAC_MATERIAL, "", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 16), b"\xe7\x76\x85\x01\x6a\x53\x62\x1e\x9a\x2a\x8a\x0f\x80\x00\x2e\x70")
        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_MAC_MATERIAL, "", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 17), b"\xe7\x76\x85\x01\x6a\x53\x62\x1e\x9a\x2a\x8a\x0f\x80\x00\x2e\x70\xfe")
        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_KEY_MATERIAL, "", b"\xbf\x0a\xaa\x4f\x84\xb4\x4e\x41\x16\x0a\x11\xb7\xed\x98\x58\xa0\x95\x3b\x4b\xf8", 2010, 2), b"\x1b\xee")

        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_MAC_MATERIAL, "password", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 0), b"")
        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_MAC_MATERIAL, "password", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 16), b"\x21\x2b\xab\x71\x42\x2d\x31\xa5\xd3\x93\x4c\x20\xe5\xe7\x7e\xb7")

        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_MAC_MATERIAL, "password", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 17), b"\x21\x2b\xab\x71\x42\x2d\x31\xa5\xd3\x93\x4c\x20\xe5\xe7\x7e\xb7\xed")
        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_KEY_MATERIAL, "password", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 17), b"\xe8\x0b\xdd\x02\x01\x55\x31\x7f\x30\xb8\x54\xcb\x9f\x78\x11\x81\x76")
        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_IV_MATERIAL,  "password", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 17), b"\x27\x68\x91\x7c\xf9\xf4\x33\xb0\xa6\x4a\x9f\xcc\xbc\x80\x5f\xd6\x48")

        fancy_password = u"\u10DA\u0028\u0CA0\u76CA\u0CA0\u10DA\u0029"
        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_KEY_MATERIAL, fancy_password, b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 129),
            b"\x5e\x3d\xab\x11\xd7\x55\x2c\xaf\x58\x2f\x61\xbd\x95\xdd\x03\xa7\x83\xa4\xf0\x2a\xeb\xdc\x86\x5c\xdb\x1e\xae\x2c\x8f\x91\x82\xa5" + \
            b"\x84\xbf\xab\x23\x75\x1c\x83\x96\x34\xcf\x0e\xc1\x6c\x84\xd7\x15\xd1\x7c\x10\x3d\x8b\xa8\xef\x1f\x63\xb4\x71\xdf\x15\x4f\xc2\x86" + \
            b"\xf9\x5c\xba\x37\xad\xd3\xe2\xb2\xaa\xb3\x37\x60\x42\x3d\x69\x29\xd1\x96\x47\x32\x6c\x41\x57\xfa\x0e\x20\x87\xd6\xa7\x40\xae\x0f" + \
            b"\xe8\x17\xd8\x8e\xda\x12\x53\xac\x7e\x19\x99\xc6\x26\x20\xed\x5d\xcd\x44\xe4\xed\x05\xb9\xdc\x39\x6a\x91\x1b\x00\xbb\x39\x3e\xd8" + \
            b"\x9b")

    def test_decrypt_PBEWithSHAAnd3KeyTripleDESCBC(self):
        fancy_password = u"\u10DA\u0028\u0CA0\u76CA\u0CA0\u10DA\u0029"
        self.assertEqual(b"sample", jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(b"\x69\xea\xff\x28\x65\x85\x0a\x68", "mypassword",   b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))
        self.assertEqual(b"sample", jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(b"\x73\xf1\xc7\x14\x74\xa3\x04\x59", fancy_password, b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))

        self.assertEqual(b"-------16-------", jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(b"\x4c\xbb\xc8\x03\x09\x35\x27\xcb\xd6\x98\x81\xba\x93\x75\x7a\x96\x60\xf2\x5b\xa9\x1e\x32\xe2\x4d", "mypassword",   b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))
        self.assertEqual(b"-------16-------", jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(b"\xe1\xce\x6d\xa1\x5b\x81\x0c\xdd\x1c\x7c\xbd\x14\x4a\x64\xc4\xa1\xda\x26\x27\xe3\x50\x87\x9d\xd1", fancy_password, b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))

        self.assertRaises(jks.util.BadDataLengthException, jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC, b"\x00", "", b"", 20)

    def test_decrypt_PBEWithSHAAndTwofishCBC(self):
        fancy_password = u"\u10DA\u0028\u0CA0\u76CA\u0CA0\u10DA\u0029"
        self.assertEqual(b"sample", jks.rfc7292.decrypt_PBEWithSHAAndTwofishCBC(b"\xc5\x22\x81\xc9\xa2\x24\x4b\x10\xf9\x1c\x6c\xbc\x67\x10\x42\x3e", "mypassword",   b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))
        self.assertEqual(b"sample", jks.rfc7292.decrypt_PBEWithSHAAndTwofishCBC(b"\xc8\xc4\x7a\xe6\xa7\xc2\x80\xd7\x05\x5f\xe2\x4f\xf4\x20\x30\x7c", fancy_password, b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))

        self.assertEqual(b"-------16-------", jks.rfc7292.decrypt_PBEWithSHAAndTwofishCBC(
            b"\xf3\x4e\x3a\xd9\x3c\x48\x42\x53\xec\x07\xef\x00\x82\x56\x30\xee\x4f\xdf\x52\x0b\x5a\xd4\x8c\x9e\xa6\x72\x19\xe4\x90\x0b\xf1\x0c", "mypassword", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))
        self.assertEqual(b"-------16-------", jks.rfc7292.decrypt_PBEWithSHAAndTwofishCBC(
            b"\xe0\xc7\x1a\xe8\xf4\x90\xca\x17\xa8\x0c\xc1\x1c\xea\x2e\x96\x38\x9d\x8d\xcc\xa4\x20\x15\x05\xa8\x57\xfa\x47\xa3\x0b\x97\xf5\x00", fancy_password, b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))

        self.assertRaises(jks.util.BadDataLengthException, jks.rfc7292.decrypt_PBEWithSHAAndTwofishCBC, b"\x00", "", b"", 20)

    def test_filter_attributes(self):
        ks = jks.KeyStore("jceks", {})
        self.assertEqual(len(list(ks.private_keys)), 0)
        self.assertEqual(len(list(ks.secret_keys)), 0)
        self.assertEqual(len(list(ks.certs)), 0)

        dummy_entries = {
            "1": jks.SecretKeyEntry(),
            "2": jks.SecretKeyEntry(),
            "3": jks.SecretKeyEntry(),
            "4": jks.TrustedCertEntry(),
            "5": jks.TrustedCertEntry(),
            "6": jks.PrivateKeyEntry()
        }
        ks = jks.KeyStore("jceks", dummy_entries)
        self.assertEqual(len(ks.private_keys), 1)
        self.assertEqual(len(ks.secret_keys), 3)
        self.assertEqual(len(ks.certs), 2)
        self.assertTrue(all(a in ks.secret_keys for a in ["1", "2", "3"]))
        self.assertTrue(all(a in ks.private_keys for a in ["6"]))
        self.assertTrue(all(a in ks.certs for a in ["4", "5"]))

        ks = jks.bks.BksKeyStore("bks", {})
        self.assertEqual(0, len(ks.certs))
        self.assertEqual(0, len(ks.secret_keys))
        self.assertEqual(0, len(ks.sealed_keys))
        self.assertEqual(0, len(ks.plain_keys))

        dummy_entries = {
            "1": jks.bks.BksSealedKeyEntry(),
            "2": jks.bks.BksSealedKeyEntry(),
            "3": jks.bks.BksSealedKeyEntry(),
            "4": jks.bks.BksKeyEntry(jks.bks.BksKeyEntry.KEY_TYPE_PRIVATE, "PKCS#8", "RSA", expected.RSA1024.private_key),
            "5": jks.bks.BksSecretKeyEntry(),
            "6": jks.bks.BksTrustedCertEntry()
        }
        ks = jks.bks.BksKeyStore("bks", dummy_entries)
        self.assertEqual(3, len(ks.sealed_keys))
        self.assertEqual(1, len(ks.secret_keys))
        self.assertEqual(1, len(ks.plain_keys))
        self.assertEqual(1, len(ks.certs))

    def test_try_decrypt_keys(self):
        # as applied to secret keys
        store = jks.KeyStore.load(KS_PATH + "/jceks/AES128.jceks", "12345678", try_decrypt_keys=False)
        sk = self.find_secret_key(store, "mykey")
        self.assertTrue(not sk.is_decrypted())
        self.assertRaises(jks.NotYetDecryptedException, lambda: sk.key)
        self.assertRaises(jks.NotYetDecryptedException, lambda: sk.key_size)
        self.assertRaises(jks.NotYetDecryptedException, lambda: sk.algorithm)

        store = jks.KeyStore.load(KS_PATH + "/jceks/AES128.jceks", "12345678", try_decrypt_keys=True)
        sk = self.find_secret_key(store, "mykey")
        self.assertTrue(sk.is_decrypted())
        dummy = sk.key
        dummy = sk.key_size
        dummy = sk.algorithm
        sk.decrypt("wrong_password") # additional decrypt() calls should do nothing

        # as applied to private keys
        store = jks.KeyStore.load(KS_PATH + "/jceks/RSA1024.jceks", "12345678", try_decrypt_keys=False)
        pk = self.find_private_key(store, "mykey")
        self.assertTrue(not pk.is_decrypted())
        self.assertRaises(jks.NotYetDecryptedException, lambda: pk.pkey)
        self.assertRaises(jks.NotYetDecryptedException, lambda: pk.pkey_pkcs8)
        self.assertRaises(jks.NotYetDecryptedException, lambda: pk.algorithm_oid)
        dummy = pk.cert_chain # not stored in encrypted form in the store, shouldn't require decryption to access

        store = jks.KeyStore.load(KS_PATH + "/jceks/RSA1024.jceks", "12345678", try_decrypt_keys=True)
        pk = self.find_private_key(store, "mykey")
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.RSA1024.private_key, expected.RSA1024.certs)
        dummy = pk.cert_chain
        pk.decrypt("wrong_password") # additional decrypt() calls should do nothing

    def test_asn1_checked_decode(self):
        bad_asn1 = b"\x00\x00" # will result in an EndOfOctets() object when decoding
        good_asn1 = expected.RSA1024.private_key

        asn1_checked_decode(good_asn1, rfc5208.PrivateKeyInfo())
        self.assertRaises(PyAsn1Error, asn1_checked_decode, bad_asn1, rfc5208.PrivateKeyInfo())

if __name__ == "__main__":
    unittest.main()
