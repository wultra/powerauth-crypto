/*
 * PowerAuth Crypto Library
 * Copyright 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.crypto.lib.util;

import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test for key conversion utilities
 * 
 * @author Petr Dvorak
 * 
 */
public class KeyConversionUtilsTest {

	private final KeyGenerator keyGenerator = new KeyGenerator();

	/**
	 * Default constructor
	 */
	public KeyConversionUtilsTest() {
	}

	/**
	 * Set up crypto providers
	 */
	@BeforeAll
	public static void setUp() {
		// Add Bouncy Castle Security Provider
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Test of convertPublicKey method, of class KeyConversionUtils.
	 * 
	 * @throws Exception In case test fails 
	 *
	 */
	@Test
	public void testConvertPublicKey() throws Exception {
		System.out.println("convertPublicKeyToBytes");
		KeyGenerator keyGenerator = new KeyGenerator();
		KeyConvertor instance = new KeyConvertor();

		PublicKey key = instance.convertBytesToPublicKey(Base64.getDecoder().decode("AsUaehWpuZseHUprd9immCELf62TTtHUGlTIXyCxY7h2"));

		for (int i = 0; i < 1000; i++) {
			KeyPair kp = keyGenerator.generateKeyPair();

			PublicKey publicKey = kp.getPublic();
			byte[] originalBytes = instance.convertPublicKeyToBytes(publicKey);
			String originalBase64 = Base64.getEncoder().encodeToString(originalBytes);
			byte[] decodedBytes = Base64.getDecoder().decode(originalBase64);
			PublicKey decodedPublicKey = instance.convertBytesToPublicKey(decodedBytes);
			assertEquals(publicKey, decodedPublicKey);

			PrivateKey privateKey = kp.getPrivate();
			byte[] originalPrivateBytes = instance.convertPrivateKeyToBytes(privateKey);
			String originalPrivateBase64 = Base64.getEncoder().encodeToString(originalPrivateBytes);
			byte[] decodedPrivateBytes = Base64.getDecoder().decode(originalPrivateBase64);
			PrivateKey decodedPrivateKey = instance.convertBytesToPrivateKey(decodedPrivateBytes);
			assertEquals(((BCECPrivateKey)privateKey).getD(), (((BCECPrivateKey)decodedPrivateKey).getD()));

			KeyFactory kf = KeyFactory.getInstance("ECDH", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
			final BigInteger keyInteger = new BigInteger("" + (12 * i + 1));
			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
			ECPrivateKeySpec pubSpec = new ECPrivateKeySpec(keyInteger, ecSpec);
			ECPrivateKey privateKey2 = (ECPrivateKey) kf.generatePrivate(pubSpec);
			originalPrivateBytes = instance.convertPrivateKeyToBytes(privateKey2);
			originalPrivateBase64 = Base64.getEncoder().encodeToString(originalPrivateBytes);
			decodedPrivateBytes = Base64.getDecoder().decode(originalPrivateBase64);
			PrivateKey decodedPrivateKey2 = instance.convertBytesToPrivateKey(decodedPrivateBytes);
			assertEquals(privateKey2, decodedPrivateKey2);
		}

	}

	@Test
	public void testConvertPoint() throws Exception {
		System.out.println("testConvertPoint");
		final KeyConvertor instance = new KeyConvertor();
		final List<byte[]> testVector = Arrays.asList(
				// Public Key 1
				Base64.getDecoder().decode("c+aNszGLNA/CfexMq3lUXLY5xS2Pqougl+OmTX3toZc="),
				Base64.getDecoder().decode("OqrmEXN5Ou7zAmDD5V0Uq4SdgRUmbtfLw2fg+anUOxU="),
				Base64.getDecoder().decode("BHPmjbMxizQPwn3sTKt5VFy2OcUtj6qLoJfjpk197aGXOqrmEXN5Ou7zAmDD5V0Uq4SdgRUmbtfLw2fg+anUOxU="),

				// Public Key 2
				Base64.getDecoder().decode("TUh1vYPq7OXRXGEacVO+pUQr8vj8elfytOV9+ebaBvo="),
				Base64.getDecoder().decode("CGvImC7L9jiStTUSRF7Z1wgdzBcuvOkUwNH7LGzlWd0="),
				Base64.getDecoder().decode("BE1Idb2D6uzl0VxhGnFTvqVEK/L4/HpX8rTlffnm2gb6CGvImC7L9jiStTUSRF7Z1wgdzBcuvOkUwNH7LGzlWd0="),

				// Public Key 3
				Base64.getDecoder().decode("CKi+0FTAiBzE+8p8luu+o0EefMUwSUQ7qEmHwzM3KvY="),
				Base64.getDecoder().decode("ANv71ruj5P2RD1a3jkFukNwhJsD/bj6fUvWD+4142RA2"),
				Base64.getDecoder().decode("BAiovtBUwIgcxPvKfJbrvqNBHnzFMElEO6hJh8MzNyr22/vWu6Pk/ZEPVreOQW6Q3CEmwP9uPp9S9YP7jXjZEDY=")
		);

		for (int i = 0; i < testVector.size() / 3; i++) {
			final int keyIndex = i * 3;
			final byte[] x = testVector.get(keyIndex);
			final byte[] y = testVector.get(keyIndex + 1);
			final byte[] encoded = testVector.get(keyIndex + 2);
			final PublicKey publicKey = instance.convertPointBytesToPublicKey(x, y);
			final PublicKey publicKeyExpected = instance.convertBytesToPublicKey(encoded);
			assertEquals(publicKeyExpected, publicKey);
		}

		// random key test
		for (int i = 0; i < 100; i++) {
			final KeyPair keyPair = keyGenerator.generateKeyPair();
			final ECPublicKey publicKeyOrig = (ECPublicKey) keyPair.getPublic();
			final byte[] bytes = instance.convertPublicKeyToBytes(publicKeyOrig);
			final byte[] x = publicKeyOrig.getW().getAffineX().toByteArray();
			final byte[] y = publicKeyOrig.getW().getAffineY().toByteArray();
			final PublicKey publicKey = instance.convertPointBytesToPublicKey(x, y);
			final PublicKey publicKeyExpected = instance.convertBytesToPublicKey(bytes);
			assertEquals(publicKeyExpected, publicKey);
		}

	}

}
