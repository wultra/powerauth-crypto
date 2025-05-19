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

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testMlKemDeterministic() throws Exception {
        // Fixed parameters for enforcing algorithm determinism
        byte[] d = Base64.getDecoder().decode("Rz06iX6CuK1WR+VWrzgS9u2fHez7i3vPbkIvnR0/Fd4=");
        byte[] z = Base64.getDecoder().decode("8i3uFSZXtlg5Y9ZK2zjpvHMyPTPv0uqfncTKe6cSgDU=");

        // Expected secret text
        byte[] ssExpected = Base64.getDecoder().decode("2rlVhy5JX5OgwKuoU4eQOQMqX0CoSUf488wX2BF1dnw=");

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
        // Ignore kemKeyPair[4] and kemKeyPair[5], these mirror input parameters
        byte[] privKey = ByteUtils.concat(s, pk, hpk, z, d);

        Method kemEncryptInternal = engineClass.getDeclaredMethod("kemEncryptInternal", byte[].class, byte[].class);
        kemEncryptInternal.setAccessible(true);
        Object ctAndSSObj = kemEncryptInternal.invoke(engine, pk, d);
        byte[][] ctAndSS = (byte[][]) ctAndSSObj;

        byte[] sharedSecret = ctAndSS[0];
        byte[] ciphertext = ctAndSS[1];

        System.out.println("# ML-KEM-768 Test Vector");
        System.out.println("pk        = " + toBase64(pk));
        System.out.println("s         = " + toBase64(s));
        System.out.println("hpk       = " + toBase64(hpk));
        System.out.println("z         = " + toBase64(z));
        System.out.println("d         = " + toBase64(d));
        System.out.println("priv      = " + toBase64(privKey));
        System.out.println("ct        = " + toBase64(ciphertext));
        System.out.println("ss        = " + toBase64(sharedSecret));

        MLKEMParameters params = MLKEMParameters.ml_kem_768;
        MLKEMPrivateKeyParameters privParams = new MLKEMPrivateKeyParameters(
                params,
                s,
                hpk,
                z,
                kemKeyPair[0],
                kemKeyPair[1],
                d
        );
        MLKEMExtractor kemExtractor = new MLKEMExtractor(privParams);
        byte[] recoveredSS = kemExtractor.extractSecret(ciphertext);
        System.out.println("recovered = " + toBase64(recoveredSS));

        assertArrayEquals(ssExpected, sharedSecret);
        assertArrayEquals(ssExpected, recoveredSS);
    }

    private static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

}

