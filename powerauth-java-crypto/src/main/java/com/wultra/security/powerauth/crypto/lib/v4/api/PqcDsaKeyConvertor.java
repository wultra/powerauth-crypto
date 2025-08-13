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

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Interface for conversion of asymmetric PQC DSA keys.
 * <p>
 * Implementations of this interface handle conversion between key objects
 * and their byte-array representations for Post-Quantum Cryptography
 * Digital Signature Algorithm (DSA) algorithms.
 *
 * @author Roman Strobl
 */
public interface PqcDsaKeyConvertor {

    /**
     * Convert a public key into a byte array.
     *
     * @param publicKey Public key instance.
     * @return Byte array representation of the public key.
     * @throws GenericCryptoException Thrown in case the conversion fails.
     */
    byte[] convertPublicKeyToBytes(PublicKey publicKey) throws GenericCryptoException;

    /**
     * Convert a byte array into a public key.
     *
     * @param keyBytes Public key bytes.
     * @return Public key instance decoded from the bytes.
     * @throws GenericCryptoException Thrown in case the conversion fails.
     */
    PublicKey convertBytesToPublicKey(byte[] keyBytes) throws GenericCryptoException;

    /**
     * Convert a private key into a byte array.
     *
     * @param privateKey Private key instance.
     * @return Byte array representation of the private key.
     * @throws GenericCryptoException Thrown in case the conversion fails.
     */
    byte[] convertPrivateKeyToBytes(PrivateKey privateKey) throws GenericCryptoException;

    /**
     * Convert a byte array into a private key.
     *
     * @param keyBytes Private key bytes.
     * @return Private key instance decoded from the bytes.
     * @throws GenericCryptoException Thrown in case the conversion fails.
     */
    PrivateKey convertBytesToPrivateKey(byte[] keyBytes) throws GenericCryptoException;

}
