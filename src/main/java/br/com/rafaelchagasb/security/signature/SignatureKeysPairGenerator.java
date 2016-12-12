package br.com.rafaelchagasb.security.signature;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;

public class SignatureKeysPairGenerator {
	
	private static final String RELATIVE_PATH_PUBLIC_KEY = "./keys/suepk";

	private static final String ALGORITHM_SIGNATURE = "SHA1withRSA";
	
	private static final String ALGORITHM_RSA = "RSA";
	
	public byte[] generate(String content) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException{
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM_RSA);
		
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		keyGen.initialize(1024, random);
		
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey priv = pair.getPrivate();
		PublicKey pub = pair.getPublic();
		
		Signature dsa = Signature.getInstance(ALGORITHM_SIGNATURE); 
		dsa.initSign(priv);
		
		dsa.update(content.getBytes(), 0, content.getBytes().length);
		
		byte[] realSig = dsa.sign();
		
		byte[] key = pub.getEncoded();
		FileOutputStream keyfos = new FileOutputStream(RELATIVE_PATH_PUBLIC_KEY);
		keyfos.write(key);
		keyfos.close();
		
		return realSig;
	}
	
	public boolean verify(byte[] signature, String content) throws Exception{
		
		FileInputStream keyfis = new FileInputStream(RELATIVE_PATH_PUBLIC_KEY);
		byte[] encKey = new byte[keyfis.available()];  
		keyfis.read(encKey);

		keyfis.close();
		
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
		
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
		
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
		
		Signature sig = Signature.getInstance(ALGORITHM_SIGNATURE);
		
		sig.initVerify(pubKey);
		
		sig.update(content.getBytes(), 0 , content.getBytes().length);
		
		return sig.verify(signature);
	}

}
