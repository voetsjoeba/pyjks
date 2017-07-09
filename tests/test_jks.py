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

if sys.version_info < (2, 7):
    import unittest2 as unittest # Python 2.6's unittest doesn't have any functionality for skipping tests
else:
    import unittest

import jks
from jks.util import *
from . import expected
from pprint import pprint

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
KS_PATH = os.path.join(CUR_PATH, 'keystores')
JAVA_TESTCASES_PATH = os.path.join(CUR_PATH, "java")

java_dumper_jar_path = None # None initially; set to path to JAR file on module setup (if successfully built)
java_dumper_main_class = "org.pyjks.KeystoreDumper"

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

try:
    long
except:
    long = int

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


class AbstractTest(unittest.TestCase):
    def find_private_key_entry(self, ks, alias):
        pke = ks.entries[alias]
        if not isinstance(pke, jks.PrivateKeyEntry):
            self.fail("Private key entry not found: %s" % alias)

        self.assertTrue(alias in ks.aliases)
        if pke.is_decrypted():
            self.assertTrue(isinstance(pke.item.key, bytes))
            self.assertTrue(isinstance(pke.item.key_pkcs8, bytes))
            self.assertTrue(isinstance(pke.item.certs, list))
            self.assertTrue(all(isinstance(tc, jks.base.TrustedCertificate) for tc in pke.item.certs))
        else:
            # if the private key entry has not yet been decrypted, its public certs are still accessible at the entry level
            self.assertTrue(isinstance(pke.certs, list))
            self.assertTrue(all(isinstance(tc, jks.base.TrustedCertificate) for tc in pke.certs))
        return pke

    def find_secret_key_entry(self, ks, alias):
        ske = ks.entries[alias]
        if not isinstance(ske, jks.SecretKeyEntry):
            self.fail("Secret key entry not found: %s" % alias)

        self.assertTrue(alias in ks.aliases)
        if ske.is_decrypted():
            self.assertTrue(isinstance(ske.item.key, bytes))
        return ske

    def find_cert_entry(self, ks, alias):
        tce = ks.entries[alias]
        if not isinstance(tce, jks.TrustedCertEntry):
            self.fail("Certificate entry not found: %s" % alias)

        self.assertTrue(alias in ks.aliases)
        self.assertTrue(isinstance(tce.item.cert, bytes))
        self.assertTrue(isinstance(tce.item.type, py23basestring))
        return tce

    def check_cert_equal(self, tc, type, cert):
        self.assertEqual(tc.type, type)
        self.assertEqual(tc.cert, cert)

    def check_pkey_and_certs_equal(self, pk, algorithm_oid, pkey_pkcs8, x509_cert_blobs):
        self.assertEqual(pk.algorithm_oid, algorithm_oid)
        self.assertEqual(pk.key_pkcs8, pkey_pkcs8)
        self.assertTrue(pk.certs is not None)
        self.assertEqual(len(pk.certs), len(x509_cert_blobs))
        for i in range(len(x509_cert_blobs)):
            self.check_cert_equal(pk.certs[i], "X.509", x509_cert_blobs[i])

    def check_secret_key_equal(self, sk, algorithm_name, key_bytes):
        self.assertEqual(sk.key, key_bytes)
        self.assertEqual(sk.key_size, len(key_bytes)*8)
        self.assertEqual(sk.algorithm, algorithm_name)

    def _test_create_and_load_keystore(self, store_type, store_pw, items_dict, entry_pws=None):
        """
        Helper function; creates a store of the given type, makes entries for the given items by alias mapping, and optionally
        encrypts the entries with the given password from the entry_pws dict (by alias).
        The store is then forwarded to save_reload_and_verify_identical to ensure that it can be successfully saved and read back out
        again by both pyjks and Java, and that both see the same content of the original store.
        """
        entry_pws = (entry_pws or {})

        store = jks.KeyStore(store_type)
        for alias, item in items_dict.items():
            entry = store.make_entry(alias, item)
            if alias in entry_pws:
                entry.encrypt(entry_pws[alias])
                self.assertTrue(not entry.is_decrypted())
            store.add_entry(entry)

        self.save_reload_and_verify_identical(store, store_pw, entry_passwords=entry_pws)

    def save_reload_and_verify_identical(self, store, store_pw, entry_passwords=None):
        """
        Given a store, saves it out and loads it back in, once with pyjks and once with Java, and verifies that both see
        the same content as in the original store.
        If any of the keys in the input store are encrypted with a different password than the store password, use the entry_passwords
        dict to pass those in so that both pyjks and Java can read out the contents of the keys.
        """
        bytez = store.saves(store_pw)
        # Note: need to re-decrypt all entries, otherwise we can't compare them later
        # TODO: consider making store.save() keep the entries decrypted
        entry_passwords = (entry_passwords or {})
        for alias, entry in store.entries.items():
            entry_pw = entry_passwords.get(alias, store_pw)
            if not entry.is_decrypted():
                entry.decrypt(entry_pw)

        store2 = jks.KeyStore.loads(bytez, store_pw)

        # verify content of store reloaded with pyjks
        self.assertTrue(store.aliases, store2.aliases)
        self.assertTrue(len(store.entries), len(store2.entries))
        self.assertTrue(set(store2.aliases), set(store2.entries.keys()))
        for alias, entry in store.entries.items():
            entry2 = store2.entries[alias]
            entry2.decrypt(entry_passwords.get(alias, store_pw))

            if isinstance(entry, jks.jks.PrivateKeyEntry):
                self.check_pkey_and_certs_equal(entry.item, entry2.item.algorithm_oid, entry2.item.key_pkcs8, [c.cert for c in entry2.item.certs])
            elif isinstance(entry, jks.jks.SecretKeyEntry):
                self.check_secret_key_equal(entry.item, entry2.item.algorithm, entry2.item.key)
            elif isinstance(entry, jks.jks.TrustedCertEntry):
                self.check_cert_equal(entry.item, entry2.item.type, entry2.item.cert)
            else:
                self.fail("Unexpected store entry")

        # verify content of store reloaded with java
        java_entry_list = None
        with tempfile_path() as path:
            with open(path, "wb") as f:
                f.write(bytez)
            java_entry_list = self.java_store2json(store.store_type, path, store_pw, entry_passwords=entry_passwords)

        self.assertTrue(store.aliases, [e["alias"] for e in java_entry_list])
        self.assertTrue(set(store.aliases), set(e["alias"] for e in java_entry_list))

        java_entries = dict((e["alias"], e) for e in java_entry_list)
        for alias, entry2 in java_entries.items():
            entry = store.entries[alias]
            if isinstance(entry, jks.jks.PrivateKeyEntry):
                name2oid = {
                    "RSA": jks.util.RSA_ENCRYPTION_OID,
                    "DSA": jks.util.DSA_OID
                }
                self.check_pkey_and_certs_equal(entry.item,
                                                name2oid[entry2["algorithm"]], java2bytes(entry2["encoded"]),
                                                [java2bytes(c["cert_data"]) for c in entry2["certs"]])
            elif isinstance(entry, jks.jks.SecretKeyEntry):
                self.check_secret_key_equal(entry.item, entry2["algorithm"], java2bytes(entry2["encoded"]))
            elif isinstance(entry, jks.jks.TrustedCertEntry):
                self.check_cert_equal(entry.item, entry2["cert_type"], java2bytes(entry2["cert_data"]))
            else:
                self.fail("Unexpected store entry")

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
        pke = self.find_private_key_entry(store, "mykey")
        self.assertEqual(store.store_type, store_type)
        self.check_pkey_and_certs_equal(pke.item, jks.util.RSA_ENCRYPTION_OID, expected.RSA1024.private_key, expected.RSA1024.certs)

    def test_rsa_1024(self):
        self._test_rsa_1024("jks")
        self._test_rsa_1024("jceks")

    def _test_rsa_2048_3certs(self, store_type):
        store = jks.KeyStore.load(KS_PATH + "/{0}/RSA2048_3certs.{0}".format(store_type), "12345678")
        pke = self.find_private_key_entry(store, "mykey")
        self.assertEqual(store.store_type, store_type)
        self.check_pkey_and_certs_equal(pke.item, jks.util.RSA_ENCRYPTION_OID, expected.RSA2048_3certs.private_key, expected.RSA2048_3certs.certs)

    def test_rsa_2048_3certs(self):
        self._test_rsa_2048_3certs("jks")
        self._test_rsa_2048_3certs("jceks")

    def _test_dsa_2048(self, store_type):
        store = jks.KeyStore.load(KS_PATH + "/{0}/DSA2048.{0}".format(store_type), "12345678")
        pke = self.find_private_key_entry(store, "mykey")
        self.assertEqual(store.store_type, store_type)
        self.check_pkey_and_certs_equal(pke.item, jks.util.DSA_OID, expected.DSA2048.private_key, expected.DSA2048.certs)

    def test_dsa_2048(self):
        self._test_dsa_2048("jks")
        self._test_dsa_2048("jceks")

    def _test_certs(self, store_type):
        store = jks.KeyStore.load(KS_PATH + "/{0}/3certs.{0}".format(store_type), "12345678")
        self.assertEqual(store.store_type, store_type)

        cert1e = self.find_cert_entry(store, "cert1")
        cert2e = self.find_cert_entry(store, "cert2")
        cert3e = self.find_cert_entry(store, "cert3")
        self.check_cert_equal(cert1e.item, "X.509", expected.RSA2048_3certs.certs[0])
        self.check_cert_equal(cert2e.item, "X.509", expected.RSA2048_3certs.certs[1])
        self.check_cert_equal(cert3e.item, "X.509", expected.RSA2048_3certs.certs[2])

    def test_certs(self):
        self._test_certs("jks")
        self._test_certs("jceks")

    def _test_custom_entry_passwords(self, store_type):
        store = jks.KeyStore.load(KS_PATH + "/{0}/custom_entry_passwords.{0}".format(store_type), "store_password")
        self.assertEqual(store.store_type, store_type)
        self.assertEqual(len(store.entries), 3 if store_type == "jceks" else 2)
        self.assertEqual(len(store.cert_entries), 1)
        self.assertEqual(len(store.private_key_entries), 1)
        self.assertEqual(len(store.secret_key_entries), 1 if store_type == "jceks" else 0)

        pke = self.find_private_key_entry(store, "private")
        self.assertRaises(jks.DecryptionFailureException, pke.decrypt, "wrong_password")
        self.assertTrue(not pke.is_decrypted())
        pke.decrypt("private_password")
        self.assertTrue(pke.is_decrypted())
        self.check_pkey_and_certs_equal(pke.item, jks.util.RSA_ENCRYPTION_OID, expected.custom_entry_passwords.private_key, expected.custom_entry_passwords.certs)

        cert = self.find_cert_entry(store, "cert")
        self.assertEqual(cert.item.cert, expected.custom_entry_passwords.certs[0])

        # JCEKS version of this store additionally contains a SecretKey
        if store_type == "jceks":
            ske = self.find_secret_key_entry(store, "secret")
            self.assertRaises(jks.DecryptionFailureException, ske.decrypt, "wrong_password")
            ske.decrypt("secret_password")
            self.assertTrue(ske.is_decrypted())
            self.assertEqual(ske.item.key, b"\x3f\x68\x05\x04\xc6\x6c\xc2\x5a\xae\x65\xd0\xfa\x49\xc5\x26\xec")
            self.assertEqual(ske.item.algorithm, "AES")
            self.assertEqual(ske.item.key_size, 128)

    def test_custom_entry_passwords(self):
        self._test_custom_entry_passwords("jks")
        self._test_custom_entry_passwords("jceks")

    def _test_duplicate_aliases(self, store_type):
        self.assertRaises(jks.DuplicateAliasException, jks.KeyStore.load, KS_PATH + "/{0}/duplicate_aliases.{0}".format(store_type), "12345678")

    def test_duplicate_aliases(self):
        self._test_duplicate_aliases("jks")
        self._test_duplicate_aliases("jceks")

    def test_non_ascii_jks_password(self):
        store = jks.KeyStore.load(KS_PATH + "/jks/non_ascii_password.jks", u"\u10DA\u0028\u0CA0\u76CA\u0CA0\u10DA\u0029")
        pke = self.find_private_key_entry(store, "mykey")
        self.assertEqual(store.store_type, "jks")
        self.check_pkey_and_certs_equal(pke.item, jks.util.RSA_ENCRYPTION_OID, expected.jks_non_ascii_password.private_key, expected.jks_non_ascii_password.certs)

class JceSecretKeyLoadTests(AbstractTest):
    """
    Tests specifically involving reading SecretKeys in JCEKS keystores
    """
    def _test_load_secret_key(self, store_path, store_pw, alias, expected_alg, expected_key):
        store = jks.KeyStore.load(KS_PATH + store_path, store_pw)
        ske = self.find_secret_key_entry(store, alias)
        self.assertEqual(store.store_type, "jceks")
        self.check_secret_key_equal(ske.item, expected_alg, expected_key)

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
          If you load a JKS keystore, don't decrypt any of the keys, and save it back out with the same store password,
          then you should get byte-identical output.
        Note: implicitly requires that saving a store outputs its entries in the same order as they were loaded/added.
        """
        with open(KS_PATH + store_path, 'rb') as file:
            keystore_bytes = file.read()
        store = jks.KeyStore.loads(keystore_bytes, store_pw, try_decrypt_keys=False)
        resaved = store.saves(store_pw)
        self.assertEqual(keystore_bytes, resaved)

    def test_load_and_save_rsa_keystore(self):
        self._test_jks_nodecrypt_roundtrip_identical("/jks/RSA1024.jks", "12345678")
    def test_load_and_save_rsa_keystore(self):
        self._test_jks_nodecrypt_roundtrip_identical("/jks/RSA2048_3certs.jks", "12345678")
    def test_load_and_save_dsa_keystore(self):
        self._test_jks_nodecrypt_roundtrip_identical("/jks/DSA2048.jks", "12345678")
    def test_load_and_save_keystore_non_ascii_password(self):
        self._test_jks_nodecrypt_roundtrip_identical("/jks/non_ascii_password.jks", u"\u10DA\u0028\u0CA0\u76CA\u0CA0\u10DA\u0029")
    def test_load_and_save_keystore_custom_entry_passwords(self):
        self._test_jks_nodecrypt_roundtrip_identical("/jks/custom_entry_passwords.jks", "store_password")
    def test_load_and_save_keystore_3certs(self):
        self._test_jks_nodecrypt_roundtrip_identical("/jks/3certs.jks", "12345678")

    # -------------------------------------------------------------------------------------------------------

    def test_create_and_load_keystore_non_ascii_password(self):
        pk = jks.PrivateKey(expected.jks_non_ascii_password.private_key, [jks.base.TrustedCertificate("X.509", data) for data in expected.jks_non_ascii_password.certs])
        items = {"mykey": pk}
        fancy_password = u"\u10DA\u0028\u0CA0\u76CA\u0CA0\u10DA\u0029"

        # Note: JCEKS stores require that the passwords for keys are ASCII-only (the store password can still be non-ASCII).
        # JKS stores have no such restriction.
        self._test_create_and_load_keystore("jks",   fancy_password, items)
        self.assertRaises(IllegalPasswordCharactersException, self._test_create_and_load_keystore, "jceks", fancy_password, items) # private key will get auto-encrypted with the store password
        self.assertRaises(IllegalPasswordCharactersException, self._test_create_and_load_keystore, "jceks", "12345678", items, entry_pws={"mykey": fancy_password}) # show that the issue is with the key's password ...
        self._test_create_and_load_keystore("jceks", fancy_password, items, entry_pws={"mykey": "12345678"}) # ... not the store password.

    def test_create_and_load_non_ascii_alias(self):
        pk = jks.PrivateKey(expected.RSA1024.private_key, [jks.base.TrustedCertificate("X.509", data) for data in expected.RSA1024.certs])
        items = {u"\xe6\xe6\xe6\xf8\xf8\xf8\xe5\xe5\xf8\xe6": pk}
        self._test_create_and_load_keystore("jks",   "12345678", items)
        self._test_create_and_load_keystore("jceks", "12345678", items)

    def test_save_oversized_alias(self):
        pk = jks.PrivateKey(expected.RSA1024.private_key, []) # dummy private key, just need some valid PKCS8-encoded blob
        items = {"a"*(0xFFFF+1): pk}
        self.assertRaises(jks.util.BadDataLengthException, self._test_create_and_load_keystore, "jks",   "12345678", items)
        self.assertRaises(jks.util.BadDataLengthException, self._test_create_and_load_keystore, "jceks", "12345678", items)

    def test_create_and_load_custom_entry_passwords(self):
        pk = jks.PrivateKey(expected.custom_entry_passwords.private_key,
                            [jks.base.TrustedCertificate("X.509", data) for data in expected.custom_entry_passwords.certs])
        items = {"mykey": pk}
        entry_pws = {"mykey": "private_password"}
        self._test_create_and_load_keystore("jks",   "store_password", items, entry_pws=entry_pws)
        self._test_create_and_load_keystore("jceks", "store_password", items, entry_pws=entry_pws)

    def test_create_and_load_keystore_pkcs8_rsa(self):
        pk = jks.PrivateKey(expected.RSA2048_3certs.private_key, [jks.base.TrustedCertificate("X.509", data) for data in expected.RSA2048_3certs.certs])
        items = {"mykey": pk}
        self._test_create_and_load_keystore("jks",   "12345678", items)
        self._test_create_and_load_keystore("jceks", "12345678", items)

    def test_create_and_load_keystore_pkcs8_dsa(self):
        pk = jks.PrivateKey(expected.DSA2048.private_key, [jks.base.TrustedCertificate("X.509", data) for data in expected.DSA2048.certs])
        items = {"mykey": pk}
        self._test_create_and_load_keystore("jks",   "12345678", items)
        self._test_create_and_load_keystore("jceks", "12345678", items)

    def test_create_and_load_keystore_raw_rsa(self):
        pk = jks.PrivateKey(expected.RSA2048_3certs.raw_private_key, [jks.base.TrustedCertificate("X.509", data) for data in expected.RSA2048_3certs.certs], key_format='rsa_raw')
        items = {"mykey": pk}
        self._test_create_and_load_keystore("jks",   "12345678", items)
        self._test_create_and_load_keystore("jceks", "12345678", items)

    def test_create_and_load_keystore_trusted_certs(self):
        items = {
            "cert1": jks.base.TrustedCertificate("X.509", expected.RSA2048_3certs.certs[0]),
            "cert2": jks.base.TrustedCertificate("X.509", expected.RSA2048_3certs.certs[1]),
            "cert3": jks.base.TrustedCertificate("X.509", expected.RSA2048_3certs.certs[2])
        }
        self._test_create_and_load_keystore("jks",   "12345678", items)
        self._test_create_and_load_keystore("jceks", "12345678", items)

    def test_create_and_load_keystore_both_trusted_and_private(self):
        pk = jks.PrivateKey(expected.RSA2048_3certs.raw_private_key,
                            [jks.base.TrustedCertificate("X.509", data) for data in expected.RSA2048_3certs.certs],
                            key_format='rsa_raw')
        store = jks.KeyStore("jks")
        store.add_entries(store.make_entries({
            "mykey": pk,
            "cert1": pk.certs[0],
            "cert2": pk.certs[1],
            "cert3": pk.certs[2],
        }))
        self.save_reload_and_verify_identical(store, "12345678")

    def test_new_keystore_duplicate_alias(self):
        cert_e1 = jks.TrustedCertEntry("cert1", int(time.time())*1000, "jks", jks.base.TrustedCertificate("X.509", expected.RSA2048_3certs.certs[0]))
        cert_e2 = jks.TrustedCertEntry("cert1", int(time.time())*1000, "jks", jks.base.TrustedCertificate("X.509", expected.RSA2048_3certs.certs[1]))
        #self.assertRaises(jks.util.DuplicateAliasException, jks.KeyStore.new, 'jks', [cert_e1, cert_e2])
        self.assertRaises(jks.util.DuplicateAliasException, jks.KeyStore, "jks", entries=[cert_e1, cert_e2])

    def test_save_invalid_keystore_format(self):
        self.assertRaises(jks.util.UnsupportedKeystoreTypeException, jks.KeyStore, 'invalid', [])

    def test_save_invalid_keystore_entry(self):
        self.assertRaises(jks.util.UnsupportedKeystoreEntryTypeException, jks.KeyStore, 'jks', entries=['string'])

class JceSecretKeySaveTests(AbstractTest):
    def test_des_secret_key(self):
        self._test_create_and_load_keystore("jceks", "12345678", {"mykey": jks.jks.SecretKey(b"\x4c\xf2\xfe\x91\x5d\x08\x2a\x43", "DES")})
    def test_desede_secret_key2(self):
        self._test_create_and_load_keystore("jceks", "12345678", {"mykey": jks.jks.SecretKey(b"\x67\x5e\x52\x45\xe9\x67\x3b\x4c\x8f\xc1\x94\xce\xec\x43\x3b\x31\x8c\x45\xc2\xe0\x67\x5e\x52\x45", "DESede")})
    def test_aes128_secret_key(self):
        self._test_create_and_load_keystore("jceks", "12345678", {"mykey": jks.jks.SecretKey(b"\x66\x6e\x02\x21\xcc\x44\xc1\xfc\x4a\xab\xf4\x58\xf9\xdf\xdd\x3c", "AES")})
    def test_aes256_secret_key(self):
        self._test_create_and_load_keystore("jceks", "12345678", {"mykey": jks.jks.SecretKey(b"\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f\x68\x77\x12\xfd\xe4\xbe\x52\xe9\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f", "AES")})
    def test_pbkdf2_hmac_sha1(self):
        self._test_create_and_load_keystore("jceks", "12345678", {"mykey": jks.jks.SecretKey(b"\x57\x95\x36\xd9\xa2\x7f\x7e\x31\x4e\xf4\xe3\xff\xa5\x76\x26\xef\xe6\x70\xe8\xf4\xd2\x96\xcd\x31\xba\x1a\x82\x7d\x9a\x3b\x1e\xe1", "PBKDF2WithHmacSHA1")})

    def test_save_jks_keystore_with_secret_key(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/AES128.jceks", "12345678")
        self.assertEqual(store.store_type, "jceks")
        store.store_type = "jks" # changing it to a jks keystore
        self.assertRaises(jks.util.UnsupportedKeystoreEntryTypeException, store.saves, '12345678')

    def test_create_jks_keystore_with_secret_key(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/AES128.jceks", "12345678")
        ske = self.find_secret_key_entry(store, "mykey")
        self.assertRaises(jks.util.UnsupportedKeystoreEntryTypeException, jks.KeyStore, "jks", [ske])

class BksOnlyTests(AbstractTest):
    def check_bks_key(self, bkskey):
        #self.assertTrue(isinstance(bkskey.format, py23basestring))
        self.assertTrue(isinstance(bkskey.algorithm, py23basestring))
        #self.assertTrue(isinstance(bkskey.encoded, bytes))

        if bkskey.type == jks.bks.BksKey.KEY_TYPE_PRIVATE:
            self.assertTrue(isinstance(bkskey.key, jks.PrivateKey))
            self.assertTrue(isinstance(bkskey.key.key_pkcs8, bytes))
            self.assertTrue(isinstance(bkskey.key.key, bytes))
            self.assertTrue(isinstance(bkskey.key.algorithm_oid, tuple))

        elif bkskey.type == jks.bks.BksKey.KEY_TYPE_PUBLIC:
            self.assertTrue(isinstance(bkskey.key, jks.PublicKey))
            self.assertTrue(isinstance(bkskey.key.key_info, bytes))
            self.assertTrue(isinstance(bkskey.key.key, bytes))
            self.assertTrue(isinstance(bkskey.key.algorithm_oid, tuple))

        elif bkskey.type == jks.bks.BksKey.KEY_TYPE_SECRET:
            self.assertTrue(isinstance(bkskey.key, jks.SecretKey))
            self.assertTrue(isinstance(bkskey.key.key, bytes))

        else:
            self.fail("No such key type: %s" % repr(key_entry.type))

    # ----- entry checks -----------------------------------------------

    def check_generic_bks_entry(self, entry, store_type):
        """Checks that apply to BKS entries of any type"""
        self.assertEqual(entry.store_type, store_type)
        #self.assertTrue(entry.is_decrypted())
        self.assertTrue(isinstance(entry.alias, py23basestring))
        self.assertTrue(isinstance(entry.timestamp, (int, long)))
        self.assertTrue(isinstance(entry.cert_chain, list))
        self.assertTrue(all(isinstance(c, jks.base.TrustedCertificate) for c in entry.cert_chain)) # TODO: check whether this ever fires

    def check_cert_entry(self, entry, store_type):
        self.assertTrue(isinstance(entry, jks.bks.BksTrustedCertEntry))
        self.check_generic_bks_entry(entry, store_type)

        self.assertTrue(entry.is_decrypted())
        self.assertTrue(isinstance(entry.item, jks.base.TrustedCertificate))
        self.assertTrue(isinstance(entry.item.cert, bytes))
        self.assertTrue(isinstance(entry.item.type, py23basestring))
        #self.assertTrue(entry.is_decrypted()) # ?

    def check_sealed_key_entry(self, entry, store_type):
        self.assertTrue(isinstance(entry, jks.bks.BksSealedKeyEntry))
        self.check_generic_bks_entry(entry, store_type)

        if entry.is_decrypted():
            self.assertTrue(isinstance(entry.item, jks.bks.BksKey))
            self.check_bks_key(entry.item)

    def check_secret_key_entry(self, entry, store_type):
        self.assertTrue(isinstance(entry, jks.bks.BksSecretKeyEntry))
        self.check_generic_bks_entry(entry, store_type)

        self.assertTrue(entry.is_decrypted())
        self.assertTrue(isinstance(entry.item, bytes))

    def check_plain_key_entry(self, key_entry, store_type, check_type=True):
        self.assertTrue(isinstance(key_entry, jks.bks.BksKeyEntry))
        self.check_generic_bks_entry(key_entry, store_type)

        self.assertTrue(key_entry.is_decrypted())
        self.check_bks_key(key_entry.item)

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
        self.assertEqual(len(store.cert_entries), 1)
        self.assertEqual(len(store.sealed_key_entries), 3)
        self.assertEqual(len(store.secret_key_entries), 1)
        self.assertEqual(len(store.plain_key_entries), 1)

        entry_sealed_public = store.entries["sealed_public_key"]
        self.check_sealed_key_entry(entry_sealed_public, store_type)
        self.assertTrue(entry_sealed_public.is_decrypted())
        self.assertEqual(entry_sealed_public.item.type, jks.bks.BksKey.KEY_TYPE_PUBLIC)
        self.assertEqual(entry_sealed_public.item.algorithm, "RSA")
        self.assertEqual(entry_sealed_public.item.key.algorithm_oid, jks.util.RSA_ENCRYPTION_OID)
        self.assertEqual(entry_sealed_public.item.key.key_info, expected.bks_christmas.public_key)

        entry_sealed_private = store.entries["sealed_private_key"]
        self.check_sealed_key_entry(entry_sealed_private, store_type)
        self.assertEqual(entry_sealed_private.item.type, jks.bks.BksKey.KEY_TYPE_PRIVATE)
        self.assertEqual(entry_sealed_private.item.algorithm, "RSA")
        self.assertTrue(entry_sealed_private.is_decrypted())
        self.check_pkey_and_certs_equal(entry_sealed_private.item.key, jks.util.RSA_ENCRYPTION_OID, expected.bks_christmas.private_key, expected.bks_christmas.certs)

        entry_sealed_secret = store.entries["sealed_secret_key"]
        self.check_sealed_key_entry(entry_sealed_secret, store_type)
        self.assertEqual(entry_sealed_secret.item.type, jks.bks.BksKey.KEY_TYPE_SECRET)
        self.assertEqual(entry_sealed_secret.item.algorithm, "AES")
        self.check_secret_key_equal(entry_sealed_secret.item.key, "AES", b"\x3f\x68\x05\x04\xc6\x6c\xc2\x5a\xae\x65\xd0\xfa\x49\xc5\x26\xec")

        entry_plain_key = store.entries["plain_key"]
        self.check_plain_key_entry(entry_plain_key, store_type)
        self.assertEqual(entry_plain_key.item.type, jks.bks.BksKey.KEY_TYPE_SECRET)
        self.assertEqual(entry_plain_key.item.algorithm, "DES")
        self.check_secret_key_equal(entry_plain_key.item.key, "DES", b"\x4c\xf2\xfe\x91\x5d\x08\x2a\x43")

        entry_cert = store.entries["cert"]
        self.check_cert_entry(entry_cert, store_type)
        self.check_cert_equal(entry_cert.item, "X.509", expected.bks_christmas.certs[0])

        entry_stored_value = store.entries["stored_value"]
        self.check_secret_key_entry(entry_stored_value, store_type)
        self.assertEqual(entry_stored_value.item, b"\x02\x03\x05\x07\x0B\x0D\x11\x13\x17")

    def _test_custom_entry_passwords(self, store, store_type):
        self.assertEqual(store.store_type, store_type)
        self.assertEqual(len(store.entries), 3)
        self.assertEqual(len(store.cert_entries), 0)
        self.assertEqual(len(store.sealed_key_entries), 3)
        self.assertEqual(len(store.secret_key_entries), 0)
        self.assertEqual(len(store.plain_key_entries), 0)

        entry_pubkey = store.entries["sealed_public_key"]
        self.assertFalse(entry_pubkey.is_decrypted())
        self.assertRaises(jks.util.NotYetDecryptedException, lambda: entry_pubkey.item)
        self.assertRaises(jks.util.DecryptionFailureException, entry_pubkey.decrypt, "wrong_password")
        entry_pubkey.decrypt("public_password")
        self.assertTrue(entry_pubkey.is_decrypted())
        self.assertEqual(entry_pubkey.item.type, jks.bks.BksKey.KEY_TYPE_PUBLIC)
        entry_pubkey.decrypt("wrong_password") # additional decrypt() calls should do nothing

        entry_private = store.entries["sealed_private_key"]
        self.assertFalse(entry_private.is_decrypted())
        self.assertRaises(jks.util.NotYetDecryptedException, lambda: entry_private.item)
        self.assertRaises(jks.util.DecryptionFailureException, entry_private.decrypt, "wrong_password")
        entry_private.decrypt("private_password")
        self.assertTrue(entry_private.is_decrypted())
        self.assertEqual(entry_private.item.type, jks.bks.BksKey.KEY_TYPE_PRIVATE)
        entry_private.decrypt("wrong_password") # additional decrypt() calls should do nothing

        entry_secret = store.entries["sealed_secret_key"]
        self.assertFalse(entry_secret.is_decrypted())
        self.assertRaises(jks.util.NotYetDecryptedException, lambda: entry_secret.item)
        self.assertRaises(jks.util.DecryptionFailureException, entry_secret.decrypt, "wrong_password")
        entry_secret.decrypt("secret_password")
        self.assertTrue(entry_secret.is_decrypted())
        self.assertEqual(entry_secret.item.type, jks.bks.BksKey.KEY_TYPE_SECRET)
        entry_secret.decrypt("wrong_password") # additional decrypt() calls should do nothing

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
        self.assertEqual(jks.bks.BksKey.type2str(jks.bks.BksKey.KEY_TYPE_PUBLIC),  "PUBLIC")
        self.assertEqual(jks.bks.BksKey.type2str(jks.bks.BksKey.KEY_TYPE_PRIVATE), "PRIVATE")
        self.assertEqual(jks.bks.BksKey.type2str(jks.bks.BksKey.KEY_TYPE_SECRET),  "SECRET")
        self.assertEqual(jks.bks.BksKey.type2str(-1),  None)


class MiscTests(AbstractTest):
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
        ks = jks.KeyStore("jks", {})
        self.assertEqual(len(list(ks.private_key_entries)), 0)
        self.assertEqual(len(list(ks.secret_key_entries)), 0)
        self.assertEqual(len(list(ks.cert_entries)), 0)

        dummy_entries = [
            jks.SecretKeyEntry("1", 0, "jceks", jks.SecretKey(b"", "AES")),
            jks.SecretKeyEntry("2", 0, "jceks", jks.SecretKey(b"", "AES")),
            jks.SecretKeyEntry("3", 0, "jceks", jks.SecretKey(b"", "AES")),
            jks.TrustedCertEntry("4", 0, "jceks", None),
            jks.TrustedCertEntry("5", 0, "jceks", None),
            jks.PrivateKeyEntry("6", 0, "jceks", b"")
        ]
        ks = jks.KeyStore("jceks", dummy_entries)
        self.assertEqual(len(ks.private_key_entries), 1)
        self.assertEqual(len(ks.secret_key_entries), 3)
        self.assertEqual(len(ks.cert_entries), 2)
        self.assertTrue(all(a in ks.secret_key_entries for a in ["1", "2", "3"]))
        self.assertTrue(all(a in ks.private_key_entries for a in ["6"]))
        self.assertTrue(all(a in ks.cert_entries for a in ["4", "5"]))

        ks = jks.bks.BksKeyStore("bks", {})
        self.assertEqual(0, len(ks.cert_entries))
        self.assertEqual(0, len(ks.secret_key_entries))
        self.assertEqual(0, len(ks.sealed_key_entries))
        self.assertEqual(0, len(ks.plain_key_entries))

        pubkey = jks.PublicKey(expected.RSA1024.public_key)
        privkey = jks.PrivateKey(expected.RSA1024.private_key, [])
        seckey = jks.SecretKey(b"", "AES")
        dummy_entries = [
            jks.bks.BksSealedKeyEntry("1", 0, "bks", [], jks.bks.BksKey.create_from(privkey)),
            jks.bks.BksSealedKeyEntry("2", 0, "bks", [], jks.bks.BksKey.create_from(pubkey)),
            jks.bks.BksSealedKeyEntry("3", 0, "bks", [], jks.bks.BksKey.create_from(seckey)),
            jks.bks.BksKeyEntry("4", 0, "bks", [], jks.bks.BksKey.create_from(pubkey)),
            jks.bks.BksSecretKeyEntry("5", 0, "bks", [], b""),
            jks.bks.BksTrustedCertEntry("6", 0, "bks", [], jks.TrustedCertificate("X.509", b""))
        ]
        ks = jks.bks.BksKeyStore("bks", dummy_entries)
        self.assertEqual(3, len(ks.sealed_key_entries))
        self.assertEqual(1, len(ks.secret_key_entries))
        self.assertEqual(1, len(ks.plain_key_entries))
        self.assertEqual(1, len(ks.cert_entries))

    def test_try_decrypt_keys(self):
        # as applied to secret keys
        store = jks.KeyStore.load(KS_PATH + "/jceks/AES128.jceks", "12345678", try_decrypt_keys=False)
        ske = self.find_secret_key_entry(store, "mykey")
        self.assertTrue(not ske.is_decrypted())
        self.assertRaises(jks.NotYetDecryptedException, lambda: ske.item)

        store = jks.KeyStore.load(KS_PATH + "/jceks/AES128.jceks", "12345678", try_decrypt_keys=True)
        ske = self.find_secret_key_entry(store, "mykey")
        self.assertTrue(ske.is_decrypted())
        dummy = ske.item.key
        dummy = ske.item.key_size
        dummy = ske.item.algorithm
        ske.decrypt("wrong_password") # additional decrypt() calls should do nothing

        # as applied to private keys
        store = jks.KeyStore.load(KS_PATH + "/jceks/RSA1024.jceks", "12345678", try_decrypt_keys=False)
        pke = self.find_private_key_entry(store, "mykey")
        self.assertTrue(not pke.is_decrypted())
        self.assertRaises(jks.NotYetDecryptedException, lambda: pke.item)
        dummy = pke.certs # not stored in encrypted form in the store, shouldn't require decryption to access

        store = jks.KeyStore.load(KS_PATH + "/jceks/RSA1024.jceks", "12345678", try_decrypt_keys=True)
        pke = self.find_private_key_entry(store, "mykey")
        self.check_pkey_and_certs_equal(pke.item, jks.util.RSA_ENCRYPTION_OID, expected.RSA1024.private_key, expected.RSA1024.certs)
        pke.decrypt("wrong_password") # additional decrypt() calls should do nothing

    def test_private_key_constructor(self):
        RSA1024_tcerts = [jks.TrustedCertificate("X.509", c) for c in expected.RSA1024.certs]

        pk = jks.PrivateKey(expected.RSA1024.private_key, RSA1024_tcerts)
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.RSA1024.private_key, expected.RSA1024.certs)

        pk = jks.PrivateKey(expected.RSA1024.private_key, RSA1024_tcerts, key_format="pkcs8")
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.RSA1024.private_key, expected.RSA1024.certs)

        self.assertRaises(Exception, jks.PrivateKey, b"key", [], key_format="ecdsa") # unsupported key format
        self.assertRaises(Exception, jks.PrivateKey, b"\x00\x00" + expected.RSA1024.private_key, [], key_format="pkcs8") # if you say it's PKCS#8, it has to be valid PKCS#8

        pk = jks.PrivateKey(b"\x00\x00", [], key_format="rsa_raw") # but a raw key can be whatever you want
        self.assertEqual(pk.key, b"\x00\x00")
        self.assertEqual(pk.algorithm_oid, jks.util.RSA_ENCRYPTION_OID)

        # ---------------------------------

        self.assertRaises(Exception, jks.PrivateKey, expected.RSA1024.private_key, [1]) # if you provide a certificate list, they have to contained TrustedCertificate instances

        certs = [jks.TrustedCertificate("X.509", b"")]
        pk = jks.PrivateKey(expected.RSA1024.private_key, certs) # if you provide a certificate list, they have to contained TrustedCertificate instances
        self.assertEqual(pk.certs, certs)

    def test_public_key_constructor(self):
        self.assertRaises(Exception, jks.PublicKey, b"\x00\x00") # input has to be a valid X.509 SubjectPublicKeyInfo
        # TODO: find a valid SubjectPublicKeyInfo struct and feed it to the constructor

    def test_trusted_certificate_constructor(self):
        cert1 = jks.TrustedCertificate("X.509", b"") # TODO: should we require a validate ASN.1 Certificate struct?
        self.assertEqual(cert1.type, "X.509")
        self.assertEqual(cert1.cert, b"")

        self.assertRaises(Exception, jks.TrustedCertificate, 1, b"") # type has to be a string
        self.assertRaises(Exception, jks.TrustedCertificate, "X.509", 1) # certificate data has to be a byte string or bytearray

    def test_secret_key_constructor(self):
        sk = jks.SecretKey(b"\x01\x02\x03", "AES")
        self.assertEqual(sk.key, b"\x01\x02\x03")
        self.assertEqual(sk.key_size, len(sk.key)*8)
        self.assertEqual(sk.algorithm, "AES")

if __name__ == "__main__":
    unittest.main()
