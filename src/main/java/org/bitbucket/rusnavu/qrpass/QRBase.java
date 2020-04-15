package org.bitbucket.rusnavu.qrpass;

import static java.util.Comparator.naturalOrder;
import static java.util.stream.Collectors.toMap;

import java.nio.charset.Charset;
import java.security.Signature;
import java.security.SignatureException;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.function.Function;
import java.util.stream.Collectors;

public class QRBase {

	private static final Charset UTF8 = Charset.forName("UTF-8");
	protected static final String SIGNATURE_KEY = "Sig";
	protected static final String SERIAL_NUMBER_KEY = "Crt";

	protected Map<String, String> updateSignature(Signature signature, Properties properties) throws SignatureException {
		return updateSignature(signature, properties.stringPropertyNames().stream().collect(toMap(Function.identity(), properties::getProperty)));
	}

	protected Map<String, String> updateSignature(Signature signature, Map<String, String> data) throws SignatureException {
		Map<String, String> map = data.keySet().stream()
				.collect(toMap(QRBase::transformChecked, ((Function<String, String>) data::get).andThen(QRBase::transformChecked)));
		List<String> keys = map.keySet().stream().sorted(naturalOrder()).collect(Collectors.toList());
		for (String key : keys) {
			signature.update(key.getBytes(UTF8));
			String value = map.get(key);
			signature.update(value.getBytes(UTF8));
		}
		return map;
	}

	public static byte[] fromHex(String string) {
		string = string.replaceAll("\\s+", "");
		int length = string.length();
		if ((length % 2) != 0)
			throw new IllegalArgumentException();
		byte[] bs = new byte[length/2];
		for (int i = 0, from = 0, to = 2; from < length; from = to, to += 2)
			bs[i++] = (byte) Integer.parseUnsignedInt(string.substring(from, to), 0x10);
		return bs;
	}

	public static String toHex(byte[] bs) {
		StringBuilder out = new StringBuilder(bs.length*2);
		for (byte b : bs)
			out.append(String.format("%02X", b));
		return out.toString();
	}

	public static String transformChecked(String s) {
		if (s.contains("\n"))
			throw new IllegalArgumentException("Multiline value");
		return transform(s);
	}

	public static String transform(String s) {
		return s.trim().replaceAll("\\s+", " ");
	}
}