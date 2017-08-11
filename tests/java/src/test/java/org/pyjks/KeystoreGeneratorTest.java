package org.pyjks;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.util.Arrays;
import org.junit.Test;

/**
 * Generates JKS/JCEKS keystores that use features available to either format.
 */
public class KeystoreGeneratorTest extends PyJksTestCase
{
	@Test
	public void generate_empty() throws Exception
	{
		generateKeyStore("JKS",   "../keystores/jks/empty.jks", null, null, "");
		generateKeyStore("JCEKS", "../keystores/jceks/empty.jceks", null, null, "");
	}

	@Test
	public void generate_RSA1024() throws Exception
	{
		KeyPair keyPair = generateKeyPair("RSA", 1024);
		Certificate cert = createSelfSignedCertificate(keyPair, "CN=RSA1024");
		Certificate[] certs = new Certificate[]{cert};

		generatePrivateKeyStore("JKS",   "../keystores/jks/RSA1024.jks",     keyPair.getPrivate(), certs);
		generatePrivateKeyStore("JCEKS", "../keystores/jceks/RSA1024.jceks", keyPair.getPrivate(), certs);

		writePythonDataFile("../expected/RSA1024.py", keyPair, certs);
	}

	@Test
	public void generate_RSA2048_3certs() throws Exception
	{
		KeyPair keyPair = generateKeyPair("RSA", 2048);

		// these do not form a chain, but that doesn't really matter for our purposes
		Certificate cert1 = createSelfSignedCertificate(keyPair, "CN=RSA2048, O=1");
		Certificate cert2 = createSelfSignedCertificate(keyPair, "CN=RSA2048, O=2");
		Certificate cert3 = createSelfSignedCertificate(keyPair, "CN=RSA2048, O=3");
		Certificate[] certs = new Certificate[]{ cert1, cert2, cert3 };

		generatePrivateKeyStore("JKS",   "../keystores/jks/RSA2048_3certs.jks",     keyPair.getPrivate(), certs);
		generatePrivateKeyStore("JCEKS", "../keystores/jceks/RSA2048_3certs.jceks", keyPair.getPrivate(), certs);

		// and while we have some certificates here anyway, we might as well produce some stores with those in them too
		String[] certAliases = new String[]{"cert1", "cert2", "cert3"};
		generateCertsKeyStore("JKS",   "../keystores/jks/3certs.jks", certs, certAliases);
		generateCertsKeyStore("JCEKS",   "../keystores/jceks/3certs.jceks", certs, certAliases);

		writePythonDataFile("../expected/RSA2048_3certs.py", keyPair, certs);
	}

	@Test
	public void generate_DSA2048() throws Exception
	{
		KeyPair keyPair = generateKeyPair("DSA", 2048);
		Certificate cert = createSelfSignedCertificate(keyPair, "CN=DSA2048");
		Certificate[] certs = new Certificate[]{ cert };

		generatePrivateKeyStore("JKS",   "../keystores/jks/DSA2048.jks",     keyPair.getPrivate(), certs);
		generatePrivateKeyStore("JCEKS", "../keystores/jceks/DSA2048.jceks", keyPair.getPrivate(), certs);

		writePythonDataFile("../expected/DSA2048.py", keyPair, certs);
	}

	@Test
	public void generate_custom_entry_passwords() throws Exception
	{
		// create JKS and JCEKS keystores containing entries of each type, each with a different entry password
		Map<String, KeyStore.Entry> entriesByAlias = new HashMap<String, KeyStore.Entry>();
		Map<String, String> passwordsByAlias = new HashMap<String, String>();

		// produce some key material
		KeyPair keyPair = generateKeyPair("RSA", 2048);
		Certificate cert = createSelfSignedCertificate(keyPair, "CN=custom_entry_passwords");
		Certificate[] certs = new Certificate[]{ cert };

		SecretKey secretKey = new SecretKeySpec(Hex.decodeHex("3f680504c66cc25aae65d0fa49c526ec".toCharArray()), "AES");

		// write JKS keystore
		entriesByAlias.put("cert", new KeyStore.TrustedCertificateEntry(cert));
		entriesByAlias.put("private", new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), certs));
		passwordsByAlias.put("private", "private_password");

		generateKeyStore("JKS", "../keystores/jks/custom_entry_passwords.jks", entriesByAlias, passwordsByAlias, "store_password");

		// add secret key entries and write JCEKS keystore
		entriesByAlias.put("secret", new KeyStore.SecretKeyEntry(secretKey));
		passwordsByAlias.put("secret", "secret_password");

		generateKeyStore("JCEKS", "../keystores/jceks/custom_entry_passwords.jceks", entriesByAlias, passwordsByAlias, "store_password");

		writePythonDataFile("../expected/custom_entry_passwords.py", keyPair, certs);
	}

	@Test
	public void generate_duplicate_aliases() throws Exception
	{
		KeyPair keyPair = generateKeyPair("RSA", 1024);
		Certificate cert1 = createSelfSignedCertificate(keyPair, "CN=duplicate_aliases, O=1");
		Certificate cert2 = createSelfSignedCertificate(keyPair, "CN=duplicate_aliases, O=2");

		String[] aliases = new String[]{"my_alias", "my_alias"};
		int[] tags = new int[]{TAG_TRUSTED_CERT, TAG_TRUSTED_CERT};
		byte[][] entriesData = new byte[][]{
			encodeTrustedCert(cert1),
			encodeTrustedCert(cert2)
		};

		generateManualStore("JKS",   "../keystores/jks/duplicate_aliases.jks",     aliases, tags, entriesData, "12345678");
		generateManualStore("JCEKS", "../keystores/jceks/duplicate_aliases.jceks", aliases, tags, entriesData, "12345678");
	}

	@Test
	public void generate_unicode_passwords() throws Exception
	{
		// In JKS keystores:
		//  - the store password can contain arbitrary unicode characters; it is taken in UTF16-BE encoded form to be mixed into the store hash
		//  - entry passwords are expected to be printable ASCII, but this is not enforced, so there's nothing stopping you from using arbitrary
		//    unicode characters anyway.
		//
		// In JCEKS keystores:
		//  - the store password is the same as in JKS, i.e. can contain arbitrary unicode characters
		//  - entry passwords must be ~printable ASCII only, and this is enforced (accepted byte range is 0x20 <= b <= 0xFE).
		//
		// Let's generate some keystores with fancy passwords and see if we can parse them.
		KeyPair keyPair = generateKeyPair("RSA", 1024);

		Certificate cert = createSelfSignedCertificate(keyPair, "CN=unicode_passwords");
		Certificate[] certs = new Certificate[]{cert};

		// use some code points from various different unicode blocks/encoding ranges and/or some special characters
		int[] codePoints = new int[]{
			0x00000000, // NUL
			0x00000041, // A                                   range 0x0000 - 0x007F
			0x000000B3, // superscript three                   range 0x0080 - 0x07FF
			0x000005E4, // hebrew letter PE                    range 0x0080 - 0x07FF
			0x0000080A, // samaritan letter kaaf               range 0x0800 - 0xD800
			0x0000D7FB, // hangul jongseong phieuph-thieuth    range 0x0800 - 0xD800
			0x0000E000, // private use area                    range 0xE000 - 0xFFFF
			0x0000FFEE, // halfwidth white circle              range 0xE000 - 0xFFFF
			0x000100A6, // linear b ideogram b158              range 0x10000 - 0x10FFFF
		};
		String fancyStorePassword = codePointsToString(codePoints);
		String fancyEntryPassword = codePointsToString(Arrays.reverse(codePoints));

		generatePrivateKeyStore("JKS",   "../keystores/jks/unicode_passwords.jks",     keyPair.getPrivate(), certs, fancyStorePassword, fancyEntryPassword, "mykey");
		generatePrivateKeyStore("JCEKS", "../keystores/jceks/unicode_passwords.jceks", keyPair.getPrivate(), certs, fancyStorePassword, "12345678", "mykey");

		writePythonDataFile("../expected/unicode_passwords.py", keyPair, certs);
	}

	@Test
	public void generate_unicode_aliases() throws Exception
	{
		KeyPair keyPair = generateKeyPair("RSA", 1024);
		Certificate cert1 = createSelfSignedCertificate(keyPair, "CN=unicode_aliases, O=1");
		Certificate cert2 = createSelfSignedCertificate(keyPair, "CN=unicode_aliases, O=2");
		Certificate[] certs = new Certificate[]{cert1, cert2};

		Map<String, KeyStore.Entry> entriesByAlias = new HashMap<String, KeyStore.Entry>();
		Map<String, String> passwordsByAlias = new HashMap<String, String>();

		// use some code points from various different unicode blocks/encoding ranges and/or some special characters
		int[] codePoints = new int[]{
			0x00000000, // NUL
			0x00000061, // a                                   range 0x0000 - 0x007F
			0x000000B3, // superscript three                   range 0x0080 - 0x07FF (note: lowercase because JKS stores will convert input aliases to lowercase)
			0x000005E4, // hebrew letter PE                    range 0x0080 - 0x07FF
			0x0000080A, // samaritan letter kaaf               range 0x0800 - 0xD800
			0x0000D7FB, // hangul jongseong phieuph-thieuth    range 0x0800 - 0xD800
			0x0000E000, // private use area                    range 0xE000 - 0xFFFF
			0x0000FFEE, // halfwidth white circle              range 0xE000 - 0xFFFF
			0x000100A6, // linear b ideogram b158              range 0x10000 - 0x10FFFF
		};
		String fancyAlias1 = codePointsToString(codePoints);
		String fancyAlias2 = codePointsToString(Arrays.reverse(codePoints)); // interesting because it ends with a null byte

		entriesByAlias.put(fancyAlias1, new KeyStore.TrustedCertificateEntry(cert1));
		entriesByAlias.put(fancyAlias2, new KeyStore.TrustedCertificateEntry(cert2));

		generateKeyStore("JKS",   "../keystores/jks/unicode_aliases.jks",     entriesByAlias, passwordsByAlias, "12345678");
		generateKeyStore("JCEKS", "../keystores/jceks/unicode_aliases.jceks", entriesByAlias, passwordsByAlias, "12345678");

		writePythonDataFile("../expected/unicode_aliases.py", null, certs);
	}
}
