/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.getlime.security.powerauth.app.cmd;

import io.getlime.security.powerauth.app.cmd.util.EncryptedStorageUtil;
import io.getlime.security.powerauth.crypto.client.keyfactory.PowerAuthClientKeyFactory;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.Security;

import static org.junit.Assert.*;

/**
 * Test command-line client implementation.
 * 
 * @author Petr Dvorak
 *
 */
public class ApplicationTest {

	/**
	 * Register crypto providers.
	 */
	@Before
	public void setUp() {
		// Add Bouncy Castle Security Provider
		Security.addProvider(new BouncyCastleProvider());
		PowerAuthConfiguration.INSTANCE.setKeyConvertor(CryptoProviderUtilFactory.getCryptoProviderUtils());
	}

	/**
	 * Test encryption of the KEY_SIGNATURE_KNOWLEDGE using the password.
	 * @throws Exception In case test fails.
	 */
	@Test
	public void testPasswordEncryption() throws Exception {

		for (int i = 0; i < 20; i++) {
			KeyPair kpd = new KeyGenerator().generateKeyPair();
			KeyPair kps = new KeyGenerator().generateKeyPair();
			SecretKey secret = new KeyGenerator().computeSharedKey(kpd.getPrivate(), kps.getPublic());

			SecretKey knowledgeSecret = new PowerAuthClientKeyFactory().generateClientSignatureKnowledgeKey(secret);
			byte[] salt = new KeyGenerator().generateRandomBytes(16);

			byte[] encrypted = EncryptedStorageUtil.storeSignatureKnowledgeKey("1234".toCharArray(), knowledgeSecret, salt, new KeyGenerator());

			// Correct password
			SecretKey knowledgeSecret2 = EncryptedStorageUtil.getSignatureKnowledgeKey("1234".toCharArray(), encrypted, salt, new KeyGenerator());
			assertEquals(knowledgeSecret, knowledgeSecret2);

			// Incorrect passwords
			SecretKey knowledgeSecret3 = EncryptedStorageUtil.getSignatureKnowledgeKey("22".toCharArray(), encrypted, salt, new KeyGenerator());
			assertNotEquals(knowledgeSecret, knowledgeSecret3);
			assertNotNull(knowledgeSecret3);
			assertEquals(knowledgeSecret.getEncoded().length, knowledgeSecret3.getEncoded().length);
			
			knowledgeSecret3 = EncryptedStorageUtil.getSignatureKnowledgeKey(" ".toCharArray(), encrypted, salt, new KeyGenerator());
			assertNotEquals(knowledgeSecret, knowledgeSecret3);
			assertNotNull(knowledgeSecret3);
			assertEquals(knowledgeSecret.getEncoded().length, knowledgeSecret3.getEncoded().length);
			
			knowledgeSecret3 = EncryptedStorageUtil.getSignatureKnowledgeKey("X123456".toCharArray(), encrypted, salt, new KeyGenerator());
			assertNotEquals(knowledgeSecret, knowledgeSecret3);
			assertNotNull(knowledgeSecret3);
			assertEquals(knowledgeSecret.getEncoded().length, knowledgeSecret3.getEncoded().length);
			
			knowledgeSecret3 = EncryptedStorageUtil.getSignatureKnowledgeKey("TestLongPasswordMore-Than 16BytesJustInCase".toCharArray(), encrypted, salt, new KeyGenerator());
			assertNotEquals(knowledgeSecret, knowledgeSecret3);
			assertNotNull(knowledgeSecret3);
			assertEquals(knowledgeSecret.getEncoded().length, knowledgeSecret3.getEncoded().length);
		}

	}

}
