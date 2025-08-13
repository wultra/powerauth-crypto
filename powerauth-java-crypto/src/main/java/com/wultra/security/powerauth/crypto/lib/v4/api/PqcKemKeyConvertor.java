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

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Interface for conversion of PQC KEM keys.
 * <p>
 * Implementations of this interface handle conversion between key objects
 * and their byte-array representations for Post-Quantum Cryptography
 * Key Encapsulation Mechanism (KEM) algorithms.
 *
 * @author Roman Strobl
 */
public interface PqcKemKeyConvertor {

    /**
     * Convert a public key for the KEM algorithm into a byte array.
     *
     * @param publicKey Public key instance.
     * @return Converted public key as a byte array.
     * @throws GenericCryptoException Thrown in case of a conversion error.
     */
    byte[] convertPublicKeyToBytes(PublicKey publicKey) throws GenericCryptoException;

    /**
     * Convert a private key for the KEM algorithm into a byte array.
     *
     * @param privateKey Private key instance.
     * @return Converted private key as a byte array.
     * @throws GenericCryptoException Thrown in case of a conversion error.
     */
    byte[] convertPrivateKeyToBytes(PrivateKey privateKey) throws GenericCryptoException;

    /**
     * Convert a byte array into a public key.
     *
     * @param publicKeyBytes Public key bytes.
     * @return Public key instance.
     * @throws GenericCryptoException Thrown in case of a conversion error.
     */
    PublicKey convertBytesToPublicKey(byte[] publicKeyBytes) throws GenericCryptoException;

    /**
     * Convert a byte array into a private key.
     *
     * @param privateKeyBytes Private key bytes.
     * @return Private key instance.
     * @throws GenericCryptoException Thrown in case of a conversion error.
     */
    PrivateKey convertBytesToPrivateKey(byte[] privateKeyBytes) throws GenericCryptoException;

    /**
     * Convert a shared secret key (used for symmetric encryption, e.g., AES) into a byte array.
     *
     * @param sharedSecretKey Shared secret key.
     * @return Converted shared secret key as a byte array.
     * @throws GenericCryptoException Thrown in case of a conversion error.
     */
    byte[] convertSharedSecretKeyToBytes(SecretKey sharedSecretKey) throws GenericCryptoException;

    /**
     * Convert a byte array into a shared secret key (used for symmetric encryption, e.g., AES).
     *
     * @param bytesSecretKey Shared secret key bytes.
     * @return Secret key instance.
     * @throws GenericCryptoException Thrown in case of a conversion error.
     */
    SecretKey convertBytesToSharedSecretKey(byte[] bytesSecretKey) throws GenericCryptoException;

}
