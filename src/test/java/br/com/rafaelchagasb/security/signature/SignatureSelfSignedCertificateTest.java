package br.com.rafaelchagasb.security.signature;

import org.junit.Assert;
import org.junit.Test;

public class SignatureSelfSignedCertificateTest {

	@Test
	public void testGenerateAndVerify() throws Exception	{
		
		String content = "teste123";
		
		byte[] signature = new SignatureSelfSignedCertificate().signature(content);
		
		Assert.assertTrue(new SignatureSelfSignedCertificate().verify(signature, content));
		
	}
	
}
