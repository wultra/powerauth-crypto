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

package io.getlime.security.powerauth.crypto.lib.v4;

import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import lombok.NoArgsConstructor;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

import java.security.*;

/**
 * Post-quantum digital signature algorithm.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@NoArgsConstructor
public class PqcDsa {

    /**
     * Generate PQC DSA keypair.
     *
     * @return Keypair.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    public KeyPair generateKeyPair() throws GenericCryptoException {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("MLDSA", "BC");
            keyPairGenerator.initialize(MLDSAParameterSpec.ml_dsa_65);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new GenericCryptoException("Error generating key pair", e);
        }
    }

    /**
     * Sign a message using PQC DSA.
     *
     * @param privateKey Private key.
     * @param message Message to sign.
     * @return Signature.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    public byte[] sign(PrivateKey privateKey, byte[] message) throws GenericCryptoException {
        try {
            final Signature mlDsa = Signature.getInstance("MLDSA");
            mlDsa.initSign(privateKey);
            mlDsa.update(message);
            return mlDsa.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new GenericCryptoException("Error during signature calculation", e);
        }
    }

    /**
     * Verify a message signature using PQC DSA.
     * @param publicKey Public key.
     * @param message Message.
     * @param signature Signature.
     * @return True if signature was correct, false otherwise.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    public boolean verify(PublicKey publicKey, byte[] message, byte[] signature) throws GenericCryptoException {
        try {
            final Signature mlDsa = Signature.getInstance("MLDSA");
            mlDsa.initVerify(publicKey);
            mlDsa.update(message);
            return mlDsa.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new GenericCryptoException("Error during signature verification", e);
        }
    }

}
