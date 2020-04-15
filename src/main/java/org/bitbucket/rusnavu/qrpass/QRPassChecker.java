package org.bitbucket.rusnavu.qrpass;

import java.io.BufferedReader;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class QRPassChecker extends QRBase {

	private static final Pattern LINE = Pattern.compile("([^:]+):\\s+(.+)");
	private final Map<BigInteger, Signature> signatures = new Hashtable<>();
	private ISignatureFactory signatureFactory;

	public void setCertificates(Collection<Certificate> certificates) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
		signatures.clear();
		for (Certificate certificate : certificates)
			addCertificate(certificate);
	}

	public void addCertificate(Certificate certificate) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
		X509Certificate x509 = (X509Certificate) certificate;
		Signature signature = signatureFactory.getSignature();
		signature.initVerify(certificate);
		signatures.put(x509.getSerialNumber(), signature);
	}

	public QRPassChecker(ISignatureFactory signatureFactory) {
		this.signatureFactory = signatureFactory;
	}

	public boolean verify(String pass) throws SignatureException {
		Map<String, String> data = new LinkedHashMap<>();
		Iterator<String> lines = new BufferedReader(new StringReader(pass)).lines().iterator();
		while (lines.hasNext()) {
			String line = lines.next();
			Matcher matcher = LINE.matcher(line);
			if (!matcher.matches())
				throw new IllegalArgumentException(line);
			data.put(transform(matcher.group(1)), matcher.group(2));
		}
		String sig = data.remove(SIGNATURE_KEY);
		if (sig == null)
			throw new IllegalArgumentException("No signature");
		String serialNumber = data.get(QRBase.SERIAL_NUMBER_KEY);
		byte[] bs = fromHex(sig);
		if (serialNumber != null) {
			Signature signature = getSignature(serialNumber);
			updateSignature(signature, data);
			return signature.verify(bs);
		} else {
			for (Signature signature : signatures.values()) {
				updateSignature(signature, data);
				try {
					if (signature.verify(bs))
						return true;
				} catch (SignatureException e) {
				}
			}
			return false;
		}
	}

	private Signature getSignature(String serialNumber) {
		Signature signature = signatures.get(new BigInteger(fromHex(serialNumber)));
		if (signature == null)
			throw new NoSuchElementException("Certificate serial number" + serialNumber);
		return signature;
	}
}
