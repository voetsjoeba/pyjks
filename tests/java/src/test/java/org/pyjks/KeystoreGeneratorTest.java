package org.pyjks;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import org.apache.commons.io.FileUtils;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Generates JKS/JCEKS keystores that use features available to either format.
 */
public class KeystoreGeneratorTest extends PyJksTestCase
{
	@BeforeClass
	public static void setUpClass() throws Exception
	{
		FileUtils.forceMkdir(new File("../keystores/jks"));
		FileUtils.forceMkdir(new File("../keystores/jceks"));
		FileUtils.forceMkdir(new File("../expected"));
	}

	@Test
	public void generate_empty() throws Exception
	{
		generatePrivateKeyStore("JKS",   "../keystores/jks/empty.jks",     null, null, "", "", "");
		generatePrivateKeyStore("JCEKS", "../keystores/jceks/empty.jceks", null, null, "", "", "");
	}

	@Test
	public void generate_RSA1024() throws Exception
	{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		Certificate cert = createSelfSignedCertificate(keyPair, "CN=RSA1024");
		Certificate[] certs = new Certificate[]{cert};

		generatePrivateKeyStore("JKS",   "../keystores/jks/RSA1024.jks",     keyPair.getPrivate(), certs);
		generatePrivateKeyStore("JCEKS", "../keystores/jceks/RSA1024.jceks", keyPair.getPrivate(), certs);

		writePythonDataFile("../expected/RSA1024.py", keyPair.getPrivate(), certs);
	}

	@Test
	public void generate_RSA2048_3certs() throws Exception
	{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// these do not form a chain, but that doesn't really matter for our purposes
		Certificate cert1 = createSelfSignedCertificate(keyPair, "CN=RSA1024, O=1");
		Certificate cert2 = createSelfSignedCertificate(keyPair, "CN=RSA1024, O=2");
		Certificate cert3 = createSelfSignedCertificate(keyPair, "CN=RSA1024, O=3");
		Certificate[] certs = new Certificate[]{ cert1, cert2, cert3 };

		generatePrivateKeyStore("JKS",   "../keystores/jks/RSA2048_3certs.jks",     keyPair.getPrivate(), certs);
		generatePrivateKeyStore("JCEKS", "../keystores/jceks/RSA2048_3certs.jceks", keyPair.getPrivate(), certs);

		writePythonDataFile("../expected/RSA2048_3certs.py", keyPair.getPrivate(), certs);
	}
}
