package org.pyjks;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.google.gson.Gson;

/**
 * Reads a keystore given on the command line and dumps out its contents in JSON format.
 * Initially created for verifying that the keystores produced by pyjks can be successfully
 * read by Java.
 *
 * Usage:
 *   KeystoreDumper &lt;storeType&gt; &lt;keystore&gt; &lt;password&gt;
 */
public class KeystoreDumper
{
	public static void usage() {
		System.err.println("Usage: $0 <storeType> <keystoreFile> <password>");
		System.exit(1);
	}

	public static void main(String[] args) throws Exception
	{
		if (args.length < 1) {
			System.err.println("ERROR: No keystore type provided on the command line.");
			usage();
		}
		if (args.length < 2) {
			System.err.println("ERROR: No keystore path provided on the command line.");
			usage();
		}
		if (args.length < 3) {
			System.err.println("ERROR: No keystore password provided on the command line.");
			usage();
		}

		String ksType = args[0].toUpperCase();
		String ksPath = args[1];
		String ksPassword = new String(Base64.decodeBase64(args[2]), "UTF-8");

		Map<String, char[]> entryPasswords = new HashMap<String, char[]>();
		if (args.length > 3 && (args.length-3) % 2 == 0) {
			for (int i=3; i < args.length; i += 2) {
				String alias   = new String(Base64.decodeBase64(args[i]), "UTF-8");
				String entryPw = new String(Base64.decodeBase64(args[i+1]), "UTF-8");
				entryPasswords.put(alias, entryPw.toCharArray());
			}
		}

		List<String> validStoreTypes = Arrays.asList("JKS", "JCEKS", "BKS", "UBER");
		if (!validStoreTypes.contains(ksType)) {
			System.err.println("ERROR: Invalid keystore type '" + ksType + "'; expected one of " + StringUtils.join(validStoreTypes, ", "));
			usage();
		}

		Provider bcProv = Security.getProvider("BC");
		if (bcProv == null)
			Security.addProvider(new BouncyCastleProvider());

		InputStream is = new BufferedInputStream(new FileInputStream(ksPath));
		try {
			KeyStore ks = KeyStore.getInstance(ksType);
			char[] ksPasswordChars = ksPassword.toCharArray();
			ks.load(is, ksPasswordChars);

			dumpKeystore(ks, ksPasswordChars, entryPasswords);
		}
		finally {
			is.close();
		}
	}

	public static void dumpKeystore(KeyStore ks, char[] ksPassword, Map<String, char[]> entryPasswords) throws Exception
	{
		Gson gson = new Gson();
		List<Object> outputList = new ArrayList<Object>();

		Enumeration<String> aliases = ks.aliases();
		while (aliases.hasMoreElements())
		{
			String alias = aliases.nextElement();
			char[] entryPassword = entryPasswords.get(alias);
			entryPassword = (entryPassword == null ? ksPassword : entryPassword);

			Map<String, Object> entryProps = new HashMap<String, Object>();
			entryProps.put("alias", alias);
			entryProps.put("timestamp", ks.getCreationDate(alias).getTime());

			if (ks.isCertificateEntry(alias))
			{
				Certificate cert = ks.getCertificate(alias);
				entryProps.put("type", "cert");
				entryProps.put("cert_data", cert.getEncoded());
				entryProps.put("cert_type", cert.getType());
			}
			else if (ks.isKeyEntry(alias))
			{
				Key key = ks.getKey(alias, entryPassword);
				Certificate[] chain = ks.getCertificateChain(alias);

				entryProps.put("encoded", key.getEncoded());
				entryProps.put("algorithm", key.getAlgorithm());

				if (chain != null) {
					List<Object> certs = new ArrayList<Object>();
					for (Certificate c : chain) {
						Map<String, Object> certProps = new HashMap<String, Object>();
						certProps.put("cert_type", c.getType());
						certProps.put("cert_data", c.getEncoded());
						certs.add(certProps);
					}
					entryProps.put("certs", certs);
				}

				if (key instanceof PrivateKey) {
					entryProps.put("type", "private");
				} else if (key instanceof PublicKey) {
					entryProps.put("type", "public");
				} else if (key instanceof SecretKey) {
					entryProps.put("type", "secret");
				}
			}

			outputList.add(entryProps);
		}

		String json = gson.toJson(outputList) + "\n";
		System.out.write(json.getBytes("UTF-8"));
		System.out.flush();
	}
}
