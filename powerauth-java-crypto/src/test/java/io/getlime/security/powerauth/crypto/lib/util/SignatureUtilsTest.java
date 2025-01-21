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

import io.getlime.security.powerauth.crypto.lib.enums.EcCurve;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link SignatureUtils}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class SignatureUtilsTest {

    private final SignatureUtils signatureUtils = new SignatureUtils();
    private KeyPair keyPairP256;
    private KeyPair keyPairP384;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator keyPairGeneratorP256 = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGeneratorP256.initialize(new ECGenParameterSpec("secp256r1"));
        keyPairP256 = keyPairGeneratorP256.generateKeyPair();

        KeyPairGenerator keyPairGeneratorP384 = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGeneratorP384.initialize(new ECGenParameterSpec("secp384r1"));
        keyPairP384 = keyPairGeneratorP384.generateKeyPair();
    }

    @Test
    void testComputeECDSASignature_Success() throws Exception {
        byte[] data = "Test data".getBytes();
        byte[] signature = signatureUtils.computeECDSASignature(EcCurve.P256, data, keyPairP256.getPrivate());
        assertNotNull(signature);
        assertTrue(signature.length > 0);
    }

    @Test
    void testComputeECDSASignature_InvalidKey() {
        byte[] data = "Test data".getBytes();
        assertThrows(InvalidKeyException.class, () ->
                signatureUtils.computeECDSASignature(EcCurve.P256, data, null)
        );
    }

    @Test
    void testValidateECDSASignatureP256_Success() throws Exception {
        byte[] data = "Test data".getBytes();
        byte[] signature = signatureUtils.computeECDSASignature(EcCurve.P256, data, keyPairP256.getPrivate());
        boolean isValid = signatureUtils.validateECDSASignature(EcCurve.P256, data, signature, keyPairP256.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testValidateECDSASignatureP256_InvalidSignature() throws Exception {
        byte[] data = "Test data".getBytes();
        byte[] invalidSignature = Base64.getDecoder().decode("MEUCIGVJAnV+cjHkoO64iaxIUBsSJjc2C2aqEvfuGgzreXLrAiEAjTqgKeQS63QuF/xSfSTr2ru/Npv+f1pwc7aPv+b8zWY=");
        boolean isValid = signatureUtils.validateECDSASignature(EcCurve.P256, data, invalidSignature, keyPairP256.getPublic());
        assertFalse(isValid);
    }

    @Test
    void testComputeECDSASignatureP384_Success() throws Exception {
        byte[] data = "Test data".getBytes();
        byte[] signature = signatureUtils.computeECDSASignature(EcCurve.P384, data, keyPairP384.getPrivate());
        assertNotNull(signature);
        assertTrue(signature.length > 0);
    }

    @Test
    void testComputeECDSASignatureP384_InvalidKey() {
        byte[] data = "Test data".getBytes();
        assertThrows(InvalidKeyException.class, () ->
                signatureUtils.computeECDSASignature(EcCurve.P384, data, null)
        );
    }

    @Test
    void testValidateECDSASignatureP384_Success() throws Exception {
        byte[] data = "Test data".getBytes();
        byte[] signature = signatureUtils.computeECDSASignature(EcCurve.P384, data, keyPairP384.getPrivate());
        boolean isValid = signatureUtils.validateECDSASignature(EcCurve.P384, data, signature, keyPairP384.getPublic());
        assertTrue(isValid);
    }

    @Test
    void testValidateECDSASignatureP384_InvalidSignature() throws Exception {
        byte[] data = "Test data".getBytes();
        byte[] invalidSignature = Base64.getDecoder().decode("MGUCMFxTfKSLjcEp7m9j+7kPG3g5+uCdINszFuNhTKQuxZJxd8UR4saU2mV8uVrnh1NSeQIxAOYHwlM1AUz5JGlZ/6K0ISgTgEsvV35U+flKtx6synobPc1hUhRDu9+c/lQFv0b/pg==");
        boolean isValid = signatureUtils.validateECDSASignature(EcCurve.P384, data, invalidSignature, keyPairP384.getPublic());
        assertFalse(isValid);
    }

}
