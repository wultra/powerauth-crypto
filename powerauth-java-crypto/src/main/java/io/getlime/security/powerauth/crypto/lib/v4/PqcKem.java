/*
 * PowerAuth Crypto Library
 * Copyright 2024 Wultra s.r.o.
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

package io.getlime.security.powerauth.crypto.lib.v4;

import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import lombok.NoArgsConstructor;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;

/**
 * Post-quantum key encapsulation mechanism.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@NoArgsConstructor
public class PqcKem {

    /**
     * Generate a PQC keypair.
     *
     * @return Keypair.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    public KeyPair generateKeyPair() throws GenericCryptoException {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ML-KEM", "BC");
            keyPairGenerator.initialize(MLKEMParameterSpec.ml_kem_768);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new GenericCryptoException("Error generating key pair", e);
        }
    }

    /**
     * Encapsulate a shared secret key using a public key.
     *
     * @param encapsulationKey Public key for encapsulation.
     * @return Secret key with encapsulation.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    public SecretKeyWithEncapsulation encapsulate(PublicKey encapsulationKey) throws GenericCryptoException {
        try {
            final KEMGenerateSpec kemGenerateSpec = new KEMGenerateSpec(encapsulationKey, "Secret");
            final KeyGenerator keyGenerator = KeyGenerator.getInstance("ML-KEM", "BC");
            keyGenerator.init(kemGenerateSpec);
            return (SecretKeyWithEncapsulation) keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new GenericCryptoException("Error during encapsulation", e);
        }
    }

    /**
     * Decapsulate a shared secret key using a private key.
     * @param decapsulationKey Private key for decapsulation.
     * @param ciphertext Encapsulation.
     * @return Secret key.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    public SecretKey decapsulate(PrivateKey decapsulationKey, byte[] ciphertext) throws GenericCryptoException {
        try {
            final KEMExtractSpec kemExtractSpec = new KEMExtractSpec(decapsulationKey, ciphertext, "Secret");
            final KeyGenerator keyGenerator = KeyGenerator.getInstance("ML-KEM", "BC");
            keyGenerator.init(kemExtractSpec);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new GenericCryptoException("Error during decapsulation", e);
        }
    }

}