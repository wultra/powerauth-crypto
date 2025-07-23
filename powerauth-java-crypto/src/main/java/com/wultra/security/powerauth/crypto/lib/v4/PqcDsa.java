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
package com.wultra.security.powerauth.crypto.lib.v4;

import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Post-quantum digital signature algorithm interface.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface PqcDsa {

    /**
     * Generate PQC DSA keypair.
     *
     * @return Keypair.
     * @throws CryptoProviderException Thrown in case the cryptography provider is incorrectly initialized.
     */
    KeyPair generateKeyPair() throws CryptoProviderException;

    /**
     * Sign a message using PQC DSA.
     *
     * @param privateKey Private key.
     * @param message Message to sign.
     * @return Signature.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    byte[] sign(PrivateKey privateKey, byte[] message) throws GenericCryptoException;

    /**
     * Verify a message signature using PQC DSA.
     * @param publicKey Public key.
     * @param message Message.
     * @param signature Signature.
     * @return True if signature was correct, false otherwise.
     * @throws GenericCryptoException Thrown in case of any cryptography error.
     */
    boolean verify(PublicKey publicKey, byte[] message, byte[] signature) throws GenericCryptoException;
}
