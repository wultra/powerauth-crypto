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
package io.getlime.security.powerauth.provider;

import io.getlime.security.powerauth.provider.exception.CryptoProviderException;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Interface for key conversion methods, used to decouple logics from
 * the implementation based on specific Java crypto provider (BC, SC, ...)
 *
 * @author Petr Dvorak
 */
public interface CryptoProviderUtil {

    /**
     * Get the provider name, for example "BC" for Bouncy Castle.
     *
     * @return Name of the provider, for example "BC" for Bouncy Castle.
     */
    String getProviderName();

    /**
     * Converts an EC public key to a byte array by encoding Q point parameter.
     *
     * @param publicKey An EC public key to be converted.
     * @return A byte array representation of the EC public key.
     */
    byte[] convertPublicKeyToBytes(PublicKey publicKey) throws CryptoProviderException;

    /**
     * Converts byte array to an EC public key, by decoding the Q point
     * parameter.
     *
     * @param keyBytes Bytes to be converted to EC public key.
     * @return An instance of the EC public key on success, or null on failure.
     * @throws InvalidKeySpecException When provided bytes are not a correct key
     *                                 representation.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     */
    PublicKey convertBytesToPublicKey(byte[] keyBytes) throws InvalidKeySpecException, CryptoProviderException;

    /**
     * Converts an EC private key to bytes by encoding the D number parameter.
     *
     * @param privateKey An EC private key to be converted to bytes.
     * @return A byte array containing the representation of the EC private key.
     */
    byte[] convertPrivateKeyToBytes(PrivateKey privateKey);

    /**
     * Convert a byte array to an EC private key by decoding the D number
     * parameter.
     *
     * @param keyBytes Bytes to be converted to the EC private key.
     * @return An instance of EC private key decoded from the input bytes.
     * @throws InvalidKeySpecException The provided key bytes are not a valid EC
     *                                 private key.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     */
    PrivateKey convertBytesToPrivateKey(byte[] keyBytes) throws InvalidKeySpecException, CryptoProviderException;

    /**
     * Converts a shared secret key (usually used for AES based operations) to a
     * byte array.
     *
     * @param sharedSecretKey A shared key to be converted to bytes.
     * @return A byte array representation of the shared secret key.
     */
    byte[] convertSharedSecretKeyToBytes(SecretKey sharedSecretKey);

    /**
     * Converts a byte array to the secret shared key (usually used for AES
     * based operations).
     *
     * @param bytesSecretKey Bytes representing the shared key.
     * @return An instance of the secret key by decoding from provided bytes.
     */
    SecretKey convertBytesToSharedSecretKey(byte[] bytesSecretKey);

}
