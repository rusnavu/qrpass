package org.bitbucket.rusnavu.qrpass;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Signature;

public interface ISignatureFactory {

	Signature getSignature() throws NoSuchAlgorithmException, NoSuchProviderException;

	static ISignatureFactory getInstance(String algorithm) {
		return new ISignatureFactory() {
			@Override
			public Signature getSignature() throws NoSuchAlgorithmException {
				return Signature.getInstance(algorithm);
			}
		};
	}

	static ISignatureFactory getInstance(String algorithm, Provider provider) {
		return new ISignatureFactory() {
			@Override
			public Signature getSignature() throws NoSuchAlgorithmException {
				return Signature.getInstance(algorithm, provider);
			}
		};
	}

	static ISignatureFactory getInstance(String algorithm, String provider) {
		return new ISignatureFactory() {
			@Override
			public Signature getSignature() throws NoSuchAlgorithmException, NoSuchProviderException {
				return Signature.getInstance(algorithm, provider);
			}
		};
	}
}
