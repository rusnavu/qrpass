package org.bitbucket.rusnavu.qrpass;

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;

public class QRPassTests {

	public static void unsureProvider() {
		Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
		if (provider == null) {
			BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
			Security.insertProviderAt(bouncyCastleProvider, 1);
		}
	}

	public static PrivateKey loadPrivateKey(String name) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		unsureProvider();
		URL url = QRPassTests.class.getResource(name);
		assertNotNull("No private key file", url);
		PEMParser pemParser = getParser(url);
		PemObject pemObject = pemParser.readPemObject();
		PrivateKeyInfo info = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(pemObject.getContent()));
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
		KeyFactory factory = KeyFactory.getInstance(info.getPrivateKeyAlgorithm().getAlgorithm().getId());
		return factory.generatePrivate(keySpec);
	}

	private static PEMParser getParser(URL resource) throws IOException {
		return new PEMParser(new BufferedReader(new InputStreamReader(resource.openStream())));
	}

	public static Certificate loadCertificate(String name) throws IOException, CertificateException {
		URL url = QRPassTests.class.getResource(name);
		assertNotNull("No certificate file", url);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		try (InputStream stream = url.openStream()) {
			return cf.generateCertificate(stream);
		}
	}

	public static final String ALGORITHM = "SHA256withRSA";
}
