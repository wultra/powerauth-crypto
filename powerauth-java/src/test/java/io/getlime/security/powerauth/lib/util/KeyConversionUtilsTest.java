/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.lib.util;

import com.google.common.io.BaseEncoding;

import io.getlime.security.powerauth.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.lib.provider.impl.CryptoProviderUtilBouncyCastle;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author petrdvorak
 */
public class KeyConversionUtilsTest {

	public KeyConversionUtilsTest() {
	}

	@BeforeClass
	public static void setUpClass() {
	}

	@AfterClass
	public static void tearDownClass() {
	}

	@Before
	public void setUp() {
		// Add Bouncy Castle Security Provider
		Security.addProvider(new BouncyCastleProvider());
		PowerAuthConfiguration.INSTANCE.setKeyConvertor(new CryptoProviderUtilBouncyCastle());
	}

	@After
	public void tearDown() {
	}

	/**
	 * Test of convertPublicKey method, of class KeyConversionUtils.
	 * 
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 */
	@Test
	public void testConvertPublicKey() throws Exception {
		System.out.println("convertPublicKeyToBytes");
		KeyGenerator keyGenerator = new KeyGenerator();
		CryptoProviderUtil instance = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

		for (int i = 0; i < 1000; i++) {
			KeyPair kp = keyGenerator.generateKeyPair();

			PublicKey publicKey = kp.getPublic();
			byte[] originalBytes = instance.convertPublicKeyToBytes(publicKey);
			String originalBase64 = BaseEncoding.base64().encode(originalBytes);
			byte[] decodedBytes = BaseEncoding.base64().decode(originalBase64);
			PublicKey decodedPublicKey = instance.convertBytesToPublicKey(decodedBytes);
			assertEquals(publicKey, decodedPublicKey);

			PrivateKey privateKey = kp.getPrivate();
			byte[] originalPrivateBytes = instance.convertPrivateKeyToBytes(privateKey);
			String originalPrivateBase64 = BaseEncoding.base64().encode(originalPrivateBytes);
			byte[] decodedPrivateBytes = BaseEncoding.base64().decode(originalPrivateBase64);
			PrivateKey decodedPrivateKey = instance.convertBytesToPrivateKey(decodedPrivateBytes);
			assertEquals(privateKey, decodedPrivateKey);

			KeyFactory kf = KeyFactory.getInstance("ECDH", PowerAuthConfiguration.INSTANCE.getKeyConvertor().getProviderName());
			BigInteger keyInteger = new BigInteger("" + (12 * i));
			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
			ECPrivateKeySpec pubSpec = new ECPrivateKeySpec(keyInteger, ecSpec);
			ECPrivateKey privateKey2 = (ECPrivateKey) kf.generatePrivate(pubSpec);
			originalPrivateBytes = instance.convertPrivateKeyToBytes(privateKey2);
			originalPrivateBase64 = BaseEncoding.base64().encode(originalPrivateBytes);
			decodedPrivateBytes = BaseEncoding.base64().decode(originalPrivateBase64);
			PrivateKey decodedPrivateKey2 = instance.convertBytesToPrivateKey(decodedPrivateBytes);
			assertEquals(privateKey2, decodedPrivateKey2);
		}

	}

}
