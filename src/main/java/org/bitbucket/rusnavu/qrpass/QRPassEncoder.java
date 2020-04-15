package org.bitbucket.rusnavu.qrpass;

import java.awt.image.BufferedImage;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import io.nayuki.qrcodegen.QrCode;

public class QRPassEncoder extends QRBase {

	private interface Initializer {

		void initSignature(Signature signature) throws InvalidKeyException;

	}
	private final ISignatureFactory signatureFactory;
	private Initializer initializer = new Initializer() {
		@Override
		public void initSignature(Signature signature) throws InvalidKeyException {
			throw new IllegalStateException("No private key");
		}
	};

	public QRPassEncoder(ISignatureFactory signatureFactory) {
		this.signatureFactory = signatureFactory;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		initializer = new Initializer() {
			@Override
			public void initSignature(Signature signature) throws InvalidKeyException {
				signature.initSign(privateKey);
			}
		};
	}

	public void setPrivateKey(PrivateKey privateKey, SecureRandom random) {
		initializer = new Initializer() {
			@Override
			public void initSignature(Signature signature) throws InvalidKeyException {
				signature.initSign(privateKey, random);
			}
		};
	}

	public String encode(Properties properties) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		Signature signature = getSignature();
		return toString(updateSignature(signature, properties), signature);
	}

	public String encode(Map<String, String> data) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		Signature signature = getSignature();
		updateSignature(signature, data);
		return toString(data, signature);
	}

	public BufferedImage encodeImage(Map<String, String> data) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		return encodeImage(data, 10, 4);
	}

	public BufferedImage encodeImage(Map<String, String> data, int scale, int border) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		String string = encode(data);
		QrCode qrCode = QrCode.encodeText(string, QrCode.Ecc.MEDIUM);
		return qrCode.toImage(scale, border);
	}

	private String toString(Map<String, String> data, Signature signature) throws SignatureException {
		return Stream.concat(data.entrySet().stream().map(e -> transform(e.getKey()) + ": " + transform(e.getValue())),
				Stream.of(QRBase.SIGNATURE_KEY + ": " + toHex(signature.sign()))).collect(Collectors.joining("\n"));
	}

	private Signature getSignature() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
		Signature signature = signatureFactory.getSignature();
		initializer.initSignature(signature);
		return signature;
	}
}
