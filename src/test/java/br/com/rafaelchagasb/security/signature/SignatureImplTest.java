package br.com.rafaelchagasb.security.signature;

import org.junit.Assert;
import org.junit.Test;

public class SignatureImplTest{
	
	@Test
	public void testGenerateAndVerify() throws Exception	{
		
		String content = "teste123";
		
		byte[] signature = new SignatureImpl().generate(content);
		
		Assert.assertTrue(new SignatureImpl().verify(signature, content));
		
	}
	
}
