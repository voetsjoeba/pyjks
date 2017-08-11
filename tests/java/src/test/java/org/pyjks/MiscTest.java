package org.pyjks;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import org.junit.Test;

public class MiscTest extends PyJksTestCase
{
	/**
	 * Encrypt some known data with PBEWithMD5AndTripleDES to verify correct decryption in python.
	 * In particular, exercise the edge case where the two salt halves are equal, because there's a bug in the JCE lurking there
	 * (see the python side for details)
	 */
	@Test
	public void generate_PBEWithMD5AndTripleDES_samples() throws Exception
	{
		byte[] output1 = encryptPBEWithMD5AndTripleDES("sample".getBytes(), "my_password", new byte[]{1,2,3,4,5,6,7,8}, 42);
		byte[] output2 = encryptPBEWithMD5AndTripleDES("sample".getBytes(), "my_password", new byte[]{1,2,3,4,1,2,3,4}, 42); // special case for SunJCE's PBEWithMD5AndTripleDES: identical salt halves
		byte[] output3 = encryptPBEWithMD5AndTripleDES("sample".getBytes(), "my_password", new byte[]{1,2,3,4,1,2,3,5}, 42); // control case for the previous one

		System.out.println(toPythonString(output1));
		System.out.println(toPythonString(output2));
		System.out.println(toPythonString(output3));
	}

	@Test
	public void generate_MUTF8_samples() throws Exception {
		// produce a bunch of sample Modified-UTF-8 strings
		System.out.println(toPythonString(mutf8_encode(new String(Character.toChars(0x000000)))));
		System.out.println(toPythonString(mutf8_encode(new String(Character.toChars(0x000001)))));
		System.out.println(toPythonString(mutf8_encode(new String(Character.toChars(0x00007F)))));
		System.out.println(toPythonString(mutf8_encode(new String(Character.toChars(0x000080)))));
		System.out.println(toPythonString(mutf8_encode(new String(Character.toChars(0x0007FF)))));
		System.out.println(toPythonString(mutf8_encode(new String(Character.toChars(0x000800)))));
		System.out.println(toPythonString(mutf8_encode(new String(Character.toChars(0x00D7FF)))));
		// reserved UTF-16 surrogate code point range 0xD800 -- 0xDFFF
		System.out.println(toPythonString(mutf8_encode(new String(Character.toChars(0x00E000)))));
		System.out.println(toPythonString(mutf8_encode(new String(Character.toChars(0x00FFFF)))));
		System.out.println(toPythonString(mutf8_encode(new String(Character.toChars(0x010000)))));
		System.out.println(toPythonString(mutf8_encode(new String(Character.toChars(0x10FFFF)))));
	}

	public byte[] mutf8_encode(String s) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);

		dos.writeUTF(s);
		dos.close();
		byte[] out = baos.toByteArray();
		// first two bytes are the length of the string, ignore those
		return Arrays.copyOfRange(out, 2, out.length);
	}

	public String mutf8_decode(byte[] input) throws IOException {
		// prefix the input byte array with its length (encoded in 2 bytes)
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		dos.writeShort(input.length);
		dos.write(input);
		dos.close();
		byte[] prefixed = baos.toByteArray();

		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(prefixed));
		return dis.readUTF();
	}
}
