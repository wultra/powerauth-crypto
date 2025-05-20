/*
 * PowerAuth Crypto Library
 * Copyright 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.crypto.lib.v4.sharedsecret;

import com.wultra.security.powerauth.crypto.lib.util.ByteUtils;
import com.wultra.security.powerauth.crypto.lib.util.PqcKemKeyConvertor;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Test for deterministic usage of ML-KEM private keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class MlKemPrivateKeyTest {

    private static final PqcKemKeyConvertor PQC_KEM_KEY_CONVERTOR = new PqcKemKeyConvertor();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testMlKemDeterministic() throws Exception {
        // Fixed parameters for enforcing algorithm determinism (seed)
        byte[] d = Base64.getDecoder().decode("Rz06iX6CuK1WR+VWrzgS9u2fHez7i3vPbkIvnR0/Fd4=");
        byte[] z = Base64.getDecoder().decode("8i3uFSZXtlg5Y9ZK2zjpvHMyPTPv0uqfncTKe6cSgDU=");

        // Use fixed byte zeroed array for KEM test
        byte[] randBytes = new byte[32];

        // Expected secret text
        byte[] ssExpected = Base64.getDecoder().decode("KmtHbzBChob2Ko4kiFWBFpQ69IXsB41g5o7Es7cwkc0=");

        Class<?> engineClass = Class.forName("org.bouncycastle.pqc.crypto.mlkem.MLKEMEngine");
        Constructor<?> engineConstructor = engineClass.getDeclaredConstructor(int.class);
        engineConstructor.setAccessible(true);
        Object engine = engineConstructor.newInstance(3); // ML-KEM-768

        Method generateKemKeyPairInternal = engineClass.getDeclaredMethod("generateKemKeyPairInternal", byte[].class, byte[].class);
        generateKemKeyPairInternal.setAccessible(true);
        byte[][] kemKeyPair = (byte[][]) generateKemKeyPairInternal.invoke(engine, d, z);

        byte[] pk = ByteUtils.concat(kemKeyPair[0], kemKeyPair[1]);
        byte[] s = kemKeyPair[2];
        byte[] hpk = kemKeyPair[3];
        assertArrayEquals(kemKeyPair[4], z);
        assertArrayEquals(kemKeyPair[5], ByteUtils.concat(d, z));
        byte[] privKeyFull = ByteUtils.concat(s, pk, hpk, z, d);
        byte[] privKeySeed = ByteUtils.concat(d, z);

        Method kemEncryptInternal = engineClass.getDeclaredMethod("kemEncryptInternal", byte[].class, byte[].class);
        kemEncryptInternal.setAccessible(true);
        Object ctAndSSObj = kemEncryptInternal.invoke(engine, pk, randBytes);
        byte[][] ctAndSS = (byte[][]) ctAndSSObj;

        byte[] sharedSecret = ctAndSS[0];
        byte[] ciphertext = ctAndSS[1];

        System.out.println("# ML-KEM-768 Test Vector (generated key, deterministic)");
        System.out.println("s         = " + toBase64(s));
        System.out.println("pk        = " + toBase64(pk));
        System.out.println("hpk       = " + toBase64(hpk));
        System.out.println("z         = " + toBase64(z));
        System.out.println("d         = " + toBase64(d));
        System.out.println("privFull  = " + toBase64(privKeyFull));
        System.out.println("privSeed  = " + toBase64(privKeySeed));
        System.out.println("ct        = " + toBase64(ciphertext));
        System.out.println("ss        = " + toBase64(sharedSecret));

        MLKEMParameters params = MLKEMParameters.ml_kem_768;
        MLKEMPrivateKeyParameters privParamsFull = new MLKEMPrivateKeyParameters(
                params,
                s,
                hpk,
                z,
                kemKeyPair[0],
                kemKeyPair[1],
                d
        );
        MLKEMExtractor kemExtractorFull = new MLKEMExtractor(privParamsFull);
        byte[] extrFull = kemExtractorFull.extractSecret(ciphertext);
        System.out.println("extrFull  = " + toBase64(extrFull));

        MLKEMPrivateKeyParameters privParamsSeed = new MLKEMPrivateKeyParameters(params, privKeySeed);
        MLKEMExtractor kemExtractorSeed = new MLKEMExtractor(privParamsSeed);
        byte[] extrSeed = kemExtractorSeed.extractSecret(ciphertext);
        System.out.println("extrSeed  = " + toBase64(extrSeed));

        assertArrayEquals(ssExpected, sharedSecret);
        assertArrayEquals(ssExpected, extrFull);
        assertArrayEquals(ssExpected, extrSeed);
    }

    @Test
    public void testMlKemPrivateKeyImportDeterministic() throws Exception {
        String clientPrivateKey = "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";
        BCMLKEMPrivateKey privateKey = (BCMLKEMPrivateKey) PQC_KEM_KEY_CONVERTOR.convertBytesToPrivateKey(Base64.getDecoder().decode(clientPrivateKey));
        BCMLKEMPublicKey publicKey = (BCMLKEMPublicKey) privateKey.getPublicKey();
        byte[] publicKeyData = publicKey.getPublicData();

        // Use fixed byte zeroed array for KEM test
        byte[] randBytes = new byte[32];

        // Expected secret text
        byte[] ssExpected = Base64.getDecoder().decode("584rvzOBFbNzZHagEtu8LYFYLY1LopmMR+Iwhr3g050=");

        Class<?> engineClass = Class.forName("org.bouncycastle.pqc.crypto.mlkem.MLKEMEngine");
        Constructor<?> engineConstructor = engineClass.getDeclaredConstructor(int.class);
        engineConstructor.setAccessible(true);
        Object engine = engineConstructor.newInstance(3); // ML-KEM-768

        Method kemEncryptInternal = engineClass.getDeclaredMethod("kemEncryptInternal", byte[].class, byte[].class);
        kemEncryptInternal.setAccessible(true);
        Object ctAndSSObj = kemEncryptInternal.invoke(engine, publicKeyData, randBytes);
        byte[][] ctAndSS = (byte[][]) ctAndSSObj;

        byte[] sharedSecret = ctAndSS[0];
        byte[] ciphertext = ctAndSS[1];

        System.out.println("# ML-KEM-768 Test Vector (imported key, deterministic)");
        System.out.println("priv      = " + clientPrivateKey);
        System.out.println("pk        = " + toBase64(publicKeyData));
        System.out.println("ct        = " + toBase64(ciphertext));
        System.out.println("ss        = " + toBase64(sharedSecret));

        assertArrayEquals(ssExpected, sharedSecret);
    }

    private static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

}

