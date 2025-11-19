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
package com.wultra.security.powerauth.crypto.lib.v4.api;

import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Key encapsulation mechanism interface.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface Kem {

    /**
     * Generate a keypair.
     *
     * @return Keypair.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    KeyPair generateKeyPair() throws GenericCryptoException;

    /**
     * Encapsulate a shared secret key using a public key.
     *
     * @param encapsulationKey Public key for encapsulation.
     * @return Secret key with encapsulation.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    SecretKeyWithEncapsulation encapsulate(PublicKey encapsulationKey) throws GenericCryptoException;

    /**
     * Decapsulate a shared secret key using a private key.
     * @param decapsulationKey Private key for decapsulation.
     * @param ciphertext Encapsulation.
     * @return Secret key.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    SecretKey decapsulate(PrivateKey decapsulationKey, byte[] ciphertext) throws GenericCryptoException;

    /**
     * Conversion method to convert public key to a byte array.
     * @param publicKey Public key.
     * @return Public key encoded as a byte array.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    byte[] convertPublicKeyToBytes(PublicKey publicKey) throws GenericCryptoException;

    /**
     * Conversion method to convert public key encoded as a byte array to a public key.
     * @param publicKeyBytes Public key encoded as a byte array.
     * @return Public key.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    PublicKey convertBytesToPublicKey(byte[] publicKeyBytes) throws GenericCryptoException;

}
