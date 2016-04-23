#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:
"""
Tests for pyjks
"""

import os, sys
import jks
import unittest
import subprocess
from pprint import pprint

class cd:
    def __init__(self, newdir):
        self.newdir = newdir
    def __enter__(self):
        self.olddir = os.getcwd()
        os.chdir(self.newdir)
    def __exit__(self, etype, value, trace):
        os.chdir(self.olddir)

class AbstractTest(unittest.TestCase):
    def find_private_key(self, ks, alias):
        for pk in ks.private_keys:
            if pk.alias == alias:
                return pk
        return None

    def find_secret_key(self, ks, alias):
        for sk in ks.secret_keys:
            if sk.alias == alias:
                return sk
        return None

    def find_cert(self, ks, alias):
        for c in ks.certs:
            if c.alias == alias:
                return c
        return None

class JceksTests(AbstractTest):
    """Note: run 'mvn test' in the tests/java directory to reproduce keystore files (requires a working Maven installation)"""
    @classmethod
    def setUpClass(cls):
        # Note: cwd is expected to be in the top-level pyjks directory
        test_dir = os.path.dirname(__file__)
        java_path = os.path.join(test_dir, "java")

    def test_empty_store(self):
        store = jks.KeyStore.load("tests/keystores/jceks/empty.jceks", "")
        self.assertEqual(len(store.private_keys), 0)
        self.assertEqual(len(store.secret_keys), 0)
        self.assertEqual(len(store.certs), 0)

    def test_des_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/DES.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(sk.key, "\x4c\xf2\xfe\x91\x5d\x08\x2a\x43")
        self.assertEqual(sk.algorithm, "DES")
        self.assertEqual(sk.size, 64)

    def test_desede_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/DESede.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(sk.key, "\x67\x5e\x52\x45\xe9\x67\x3b\x4c\x8f\xc1\x94\xce\xec\x43\x3b\x31\x8c\x45\xc2\xe0\x67\x5e\x52\x45")
        self.assertEqual(sk.algorithm, "DESede")
        self.assertEqual(sk.size, 192)

    def test_aes128_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/AES128.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(sk.key, "\x66\x6e\x02\x21\xcc\x44\xc1\xfc\x4a\xab\xf4\x58\xf9\xdf\xdd\x3c")
        self.assertEqual(sk.algorithm, "AES")
        self.assertEqual(sk.size, 128)

    def test_aes256_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/AES256.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(sk.key, "\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f\x68\x77\x12\xfd\xe4\xbe\x52\xe9\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f")
        self.assertEqual(sk.algorithm, "AES")
        self.assertEqual(sk.size, 256)

    def test_pbkdf2_hmac_sha1(self):
        store = jks.KeyStore.load("tests/keystores/jceks/PBKDF2WithHmacSHA1.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(sk.key, "\x57\x95\x36\xd9\xa2\x7f\x7e\x31\x4e\xf4\xe3\xff\xa5\x76\x26\xef\xe6\x70\xe8\xf4\xd2\x96\xcd\x31\xba\x1a\x82\x7d\x9a\x3b\x1e\xe1")
        self.assertEqual(sk.algorithm, "PBKDF2WithHmacSHA1")
        self.assertEqual(sk.size, 256)

    def test_rsa_1024(self):
        store = jks.KeyStore.load("tests/keystores/jceks/RSA1024.jceks", "12345678")
        pk = self.find_private_key(store, "mykey")
        expected_key = "\x30\x82\x02\x75\x02\x01\x00\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x04\x82\x02\x5f\x30\x82\x02\x5b\x02\x01" +\
                       "\x00\x02\x81\x81\x00\xc8\x93\x19\xc4\x91\x24\xe7\xb2\x42\x08\xa1\xf5\x00\x58\x81\x15\xbe\x61\x14\x23\x06\x44\xf4\xbe\xa5\x78\xc1" +\
                       "\x51\xdc\xfa\xa5\x22\xd4\xc6\xff\x49\x2b\x69\x90\x24\xdc\x79\x5d\xd5\x43\x98\x3f\x1d\xbf\x71\x9f\xc6\x4c\x15\x25\x28\xbf\x26\xa3" +\
                       "\x44\x29\xe0\xea\xc3\x68\xd4\x94\xa6\xa1\x16\x74\xf7\x04\x3b\xa2\xf1\xb7\x3a\x2d\x99\x2e\xe8\x59\x8d\x2a\x28\x17\x40\x24\x37\xf4" +\
                       "\xaf\xd0\xd6\xb9\xc7\xd7\x55\x63\xdd\xce\x99\xd7\xdd\x02\x49\xad\x70\x61\x3e\x7a\x3f\xf7\x63\x01\x01\x4a\xcd\xab\xd7\x3e\x47\x8b" +\
                       "\x6d\xe7\x84\x25\xd7\x02\x03\x01\x00\x01\x02\x81\x80\x53\xda\xa3\xf0\x39\x1a\x2b\xbf\xab\xb9\xbe\x34\x16\xa3\xe9\xbb\xb4\x6f\x13" +\
                       "\xa3\x1c\xf0\xe1\x3d\x7f\x22\x7f\xf8\x00\xa1\xcd\x3e\x45\xa4\xb8\x7f\xd7\xa5\x77\x7c\xe1\xab\xdf\xdd\xd4\x37\xa7\x53\x81\x81\x38" +\
                       "\x62\x07\xd6\xe3\x45\x28\xbd\x37\x8e\xbc\xcf\x6a\x75\xef\xa3\x1f\x71\xd0\x7a\x8b\x94\x78\x44\xbe\xb3\x42\x80\x7d\x43\xf5\x5d\x6e" +\
                       "\x24\xe2\x34\x7f\x4e\xb2\x09\xbc\x1c\x83\x6a\x30\x72\x66\x23\x3e\x5e\x33\x69\xd6\x6f\x56\xa1\x50\x02\x4c\xc0\x9e\xaa\xd3\x91\x01" +\
                       "\x82\x16\x9e\x8f\xbc\x57\x8d\x4b\x33\xee\x4d\xf1\xd1\x02\x41\x00\xf5\x34\x2e\x46\x02\xdf\xc1\x1b\x1c\xcb\x44\xa4\xc9\xb2\x47\x35" +\
                       "\x02\x3d\x0f\x97\xeb\x80\x5e\x70\xe5\x2c\x82\x85\x70\xd9\x5c\x79\xfc\x79\x1c\x35\xaa\x44\x47\x56\xba\x9b\x49\xfa\x42\xba\x3f\xb9" +\
                       "\xf0\xdb\xcf\x41\x11\x51\xc8\xcf\xda\xab\xf8\x7f\x59\x14\xc7\xff\x02\x41\x00\xd1\x67\xe1\x81\x62\xd5\x3d\xae\xf6\xb4\x3d\x39\x8c" +\
                       "\x38\xbc\x46\xc1\x6b\xfd\xed\x81\x51\x1a\x8e\xf8\x41\x4a\x65\xcd\xaf\x1f\xc3\x50\x94\xd5\xe3\x28\x2c\x8c\x64\xa2\x40\x07\x0f\x09" +\
                       "\x1e\xf1\x31\x3b\x5d\xdb\xc0\xd7\x0b\x89\xd4\x08\xf8\x81\x79\xed\x5f\xe2\x29\x02\x40\x44\x93\xc0\x71\x52\x32\x74\x16\x7a\x1a\x1b" +\
                       "\x6b\x9f\x01\x5e\x4a\xe4\x02\x61\xcf\x12\x4d\x47\x9c\x79\x6b\xd6\x61\x2d\xab\x8c\xe2\x8d\x0a\xee\x29\xd0\x21\xe2\x75\xce\x20\xca" +\
                       "\x32\xd4\xe0\xb4\x1b\xf3\xd1\xf6\x07\xf3\xa9\x14\xe9\x94\xf5\xcd\xbd\x08\x13\xf8\xcf\x02\x40\x5e\xaf\x2a\xee\xf7\x02\x56\x76\xc3" +\
                       "\x44\x32\x1e\xd0\x41\x63\x18\x57\x22\xfe\x59\x22\xcc\xca\x46\x75\x08\x08\x9c\xc9\x88\xf2\xc2\xbc\xaf\xdf\x9a\x6b\xb2\xe0\xf4\x2b" +\
                       "\xcc\xe9\xa4\x29\xca\x9c\xe2\x56\xe6\x94\x93\xb8\x68\x96\x34\x92\xad\xd2\xd5\x8f\xb8\x78\x29\x02\x40\x35\xed\x79\x49\x45\x44\xf0" +\
                       "\xb2\x3a\x5d\x7f\xc3\x7f\xbc\x53\x50\x25\x1e\xab\x54\xe1\x88\xfd\xba\x36\x85\xfe\x3f\x7d\x0d\xd6\xda\x03\xdb\x98\xc3\x2b\xc7\x2f" +\
                       "\xef\x08\x01\x27\x6e\x04\x38\x44\xd6\x3f\x65\x7f\x9f\xaa\xa3\x05\x29\xeb\xa2\x22\x4b\x7c\x11\x84\xa7"
        expected_cert = "\x30\x82\x01\x98\x30\x82\x01\x01\xa0\x03\x02\x01\x02\x02\x01\x00\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x30" +\
                        "\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x03\x0c\x07\x52\x53\x41\x31\x30\x32\x34\x30\x1e\x17\x0d\x31\x36\x30\x34\x32\x33\x31\x36\x30" +\
                        "\x30\x34\x30\x5a\x17\x0d\x31\x38\x30\x34\x32\x33\x31\x36\x30\x30\x34\x30\x5a\x30\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x03\x0c\x07" +\
                        "\x52\x53\x41\x31\x30\x32\x34\x30\x81\x9f\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\x8d\x00\x30\x81\x89" +\
                        "\x02\x81\x81\x00\xc8\x93\x19\xc4\x91\x24\xe7\xb2\x42\x08\xa1\xf5\x00\x58\x81\x15\xbe\x61\x14\x23\x06\x44\xf4\xbe\xa5\x78\xc1\x51" +\
                        "\xdc\xfa\xa5\x22\xd4\xc6\xff\x49\x2b\x69\x90\x24\xdc\x79\x5d\xd5\x43\x98\x3f\x1d\xbf\x71\x9f\xc6\x4c\x15\x25\x28\xbf\x26\xa3\x44" +\
                        "\x29\xe0\xea\xc3\x68\xd4\x94\xa6\xa1\x16\x74\xf7\x04\x3b\xa2\xf1\xb7\x3a\x2d\x99\x2e\xe8\x59\x8d\x2a\x28\x17\x40\x24\x37\xf4\xaf" +\
                        "\xd0\xd6\xb9\xc7\xd7\x55\x63\xdd\xce\x99\xd7\xdd\x02\x49\xad\x70\x61\x3e\x7a\x3f\xf7\x63\x01\x01\x4a\xcd\xab\xd7\x3e\x47\x8b\x6d" +\
                        "\xe7\x84\x25\xd7\x02\x03\x01\x00\x01\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x03\x81\x81\x00\x71\x3e\x47\xce" +\
                        "\x75\xdc\x02\x6d\x8d\xb2\x87\x84\x67\x8a\x9d\x5d\x4c\x58\x11\x68\x98\x5e\x90\x7e\xe9\x59\x58\xe4\xa6\xf7\xd0\xb7\x5c\x8c\xe0\xb3" +\
                        "\x0d\x20\x83\x4a\x1a\x63\x01\x22\x45\x2c\x9a\x60\xa1\x58\xef\x43\x94\x69\x3e\x33\x23\x56\x72\x58\x16\x0a\x6f\x2a\x8b\xac\x41\xfb" +\
                        "\x16\xd2\x98\xdb\x1c\x9b\x1b\x94\xc5\xe7\xf9\x76\xe3\xbe\x24\xd8\xe0\x61\x8c\x26\x49\x9b\x58\xd4\x7c\xad\x53\x36\x25\x0f\x5c\xbb" +\
                        "\xc5\x9d\xfb\x0f\x8d\xba\x1c\xf5\x52\x1a\x9c\x27\x74\x58\xc4\x05\xf6\x97\xc8\xa4\xe7\x9a\xdc\x4b\xe1\x00\x37\x82"

        self.assertEqual(pk.pkey_pkcs8, expected_key)
        self.assertEqual(pk.algorithm_oid, jks.RSA_ENCRYPTION_OID)
        self.assertEqual(len(pk.cert_chain), 1)
        self.assertEqual(pk.cert_chain[0][1], expected_cert)

if __name__ == "__main__":
    unittest.main()
