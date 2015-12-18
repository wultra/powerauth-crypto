package io.getlime.security.client.app;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.Security;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import io.getlime.security.powerauth.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;

public class ApplicationTest {

	@Before
	public void setUp() {
		// Add Bouncy Castle Security Provider
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testPasswordEncryption() throws Exception {

		Application app = new Application();

		for (int i = 0; i < 20; i++) {
			KeyPair kpd = new KeyGenerator().generateKeyPair();
			KeyPair kps = new KeyGenerator().generateKeyPair();
			SecretKey secret = new KeyGenerator().computeSharedKey(kpd.getPrivate(), kps.getPublic());

			SecretKey knowledgeSecret = new PowerAuthClientKeyFactory().generateClientSignatureKnowledgeKey(secret);
			byte[] salt = new KeyGenerator().generateRandomBytes(16);

			byte[] encrypted = app.storeSignatureKnowledgeKey("1234".toCharArray(), knowledgeSecret, salt, new KeyGenerator());

			// Correct password
			SecretKey knowledgeSecret2 = app.getSignatureKnowledgeKey("1234".toCharArray(), encrypted, salt, new KeyGenerator());
			assertEquals(knowledgeSecret, knowledgeSecret2);

			// Incorrect passwords
			SecretKey knowledgeSecret3 = app.getSignatureKnowledgeKey("22".toCharArray(), encrypted, salt, new KeyGenerator());
			assertNotEquals(knowledgeSecret, knowledgeSecret3);
			assertNotNull(knowledgeSecret3);
			assertEquals(knowledgeSecret.getEncoded().length, knowledgeSecret3.getEncoded().length);
			
			knowledgeSecret3 = app.getSignatureKnowledgeKey("".toCharArray(), encrypted, salt, new KeyGenerator());
			assertNotEquals(knowledgeSecret, knowledgeSecret3);
			assertNotNull(knowledgeSecret3);
			assertEquals(knowledgeSecret.getEncoded().length, knowledgeSecret3.getEncoded().length);
			
			knowledgeSecret3 = app.getSignatureKnowledgeKey("X123456".toCharArray(), encrypted, salt, new KeyGenerator());
			assertNotEquals(knowledgeSecret, knowledgeSecret3);
			assertNotNull(knowledgeSecret3);
			assertEquals(knowledgeSecret.getEncoded().length, knowledgeSecret3.getEncoded().length);
			
			knowledgeSecret3 = app.getSignatureKnowledgeKey("TestLongPasswordMore-Than 16BytesJustInCase".toCharArray(), encrypted, salt, new KeyGenerator());
			assertNotEquals(knowledgeSecret, knowledgeSecret3);
			assertNotNull(knowledgeSecret3);
			assertEquals(knowledgeSecret.getEncoded().length, knowledgeSecret3.getEncoded().length);
		}

	}

}
