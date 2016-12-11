package br.com.rafaelchagasb.security.signature;

import org.junit.Assert;
import org.junit.Test;

public class SignatureKeysPairGeneratorTest{
	
	@Test
	public void testGenerateAndVerify() throws Exception	{
		
		String content = "teste123";
		
		byte[] signature = new SignatureKeysPairGenerator().generate(content);
		
		Assert.assertTrue(new SignatureKeysPairGenerator().verify(signature, content));
		
	}
	
}
