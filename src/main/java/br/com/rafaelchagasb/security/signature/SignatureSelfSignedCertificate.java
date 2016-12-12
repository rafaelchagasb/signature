package br.com.rafaelchagasb.security.signature;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;

public class SignatureSelfSignedCertificate {
	
	private static final String RELATIVE_PATH_KEYSTORE = "./keys/keystore.jks";

	private static final String TYPE_KEYSTORE = "JKS";

	private static final String ALGORITHM = "SHA1withRSA";

	private static final char[] CHAR_PASSWORD = "changeit".toCharArray();
	
	private static final String ALIAS_CERTIFICATE = "self-signed-certificate";
	
	public byte[] signature(String content) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, UnrecoverableEntryException, InvalidKeyException, SignatureException {

		KeyStore ks = KeyStore.getInstance(TYPE_KEYSTORE);
		
		FileInputStream fileInputStream = new FileInputStream(new File(RELATIVE_PATH_KEYSTORE));

		ks.load(fileInputStream, CHAR_PASSWORD);
		
		PasswordProtection protection = new PasswordProtection(CHAR_PASSWORD);
		
		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(ALIAS_CERTIFICATE, protection);
		
		RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();
		
		Signature dsa = Signature.getInstance(ALGORITHM); 
		
		dsa.initSign(privateKey);
		
		dsa.update(content.getBytes(), 0, content.getBytes().length);
		
		return dsa.sign();
	}
	
	public boolean verify(byte[] signature, String content) throws Exception{
		
		KeyStore trustStore = KeyStore.getInstance(TYPE_KEYSTORE);
		
		FileInputStream fileInputStream = new FileInputStream(new File(RELATIVE_PATH_KEYSTORE));

		trustStore.load(fileInputStream, CHAR_PASSWORD);
		
		Certificate certificate = trustStore.getCertificate(ALIAS_CERTIFICATE);
		
		Signature sig = Signature.getInstance(ALGORITHM);
		
		sig.initVerify(certificate.getPublicKey());
		
		sig.update(content.getBytes(), 0 , content.getBytes().length);
		
		return sig.verify(signature);
	}
}
