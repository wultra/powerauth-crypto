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
package com.wultra.security.powerauth.crypto.lib.util;

import com.wultra.security.powerauth.crypto.lib.v4.PqcDsa;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test for key conversion for PQC DSA.
 * 
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PqcDsaKeyConvertorTest {

	private final PqcDsaKeyConvertor KEY_CONVERTOR = new PqcDsaKeyConvertor();
	private final PqcDsa PQC_DSA = new PqcDsa();

	private static final String PUBLIC_KEY_BASE64 = "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";
	private static final String PRIVATE_KEY_BASE64 = "MDICAQAwCwYJYIZIAWUDBAMSBCAtie/N/WXwodhUNcaNUDOOHL8StjZUn+vU7MzwrDhrFQ==";

	/**
	 * Set up BC provider.
	 */
	@BeforeAll
	public static void setUp() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testKeyConversionPqcDsa_GeneratedKey() throws Exception {
		final KeyPair keyPair = PQC_DSA.generateKeyPair();
		final byte[] publicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(keyPair.getPublic());
		final PublicKey publicKeyActual = KEY_CONVERTOR.convertBytesToPublicKey(publicKeyBytes);
		assertEquals(keyPair.getPublic(), publicKeyActual);
		final byte[] privateKeyBytes = KEY_CONVERTOR.convertPrivateKeyToBytes(keyPair.getPrivate());
		final PrivateKey privateKeyActual = KEY_CONVERTOR.convertBytesToPrivateKey(privateKeyBytes);
		assertEquals(keyPair.getPrivate(), privateKeyActual);
	}

	@Test
	public void testKeyConversionPqcDsa_ImportedKey() throws Exception {
		final PublicKey publicKeyImported = KEY_CONVERTOR.convertBytesToPublicKey(Base64.getDecoder().decode(PUBLIC_KEY_BASE64));
		final byte[] publicKeyBytes = KEY_CONVERTOR.convertPublicKeyToBytes(publicKeyImported);
		assertEquals(PUBLIC_KEY_BASE64, Base64.getEncoder().encodeToString(publicKeyBytes));
		final PrivateKey privateKeyImported = KEY_CONVERTOR.convertBytesToPrivateKey(Base64.getDecoder().decode(PRIVATE_KEY_BASE64));
		final byte[] privateKeyBytes = KEY_CONVERTOR.convertPrivateKeyToBytes(privateKeyImported);
		assertEquals(PRIVATE_KEY_BASE64, Base64.getEncoder().encodeToString(privateKeyBytes));
	}

}
