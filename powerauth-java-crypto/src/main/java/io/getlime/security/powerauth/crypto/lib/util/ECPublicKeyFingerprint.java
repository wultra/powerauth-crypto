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

import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.model.ActivationVersion;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * Class that is used for computing EC public key fingerprint. Goal of the public key fingerprint is to
 * enable user to visually check that the public key was successfully exchanged between client and server.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class ECPublicKeyFingerprint {

    private static final Logger logger = LoggerFactory.getLogger(ECPublicKeyFingerprint.class);

    /**
     * Compute activation fingerprint.
     *
     * @param devicePublicKey Device public key.
     * @param serverPublicKey Server public key, null for activation version 2.
     * @param activationId Activation ID, null for activation version 2.
     * @param activationVersion Activation version.
     * @return Activation fingerprint.
     * @throws GenericCryptoException Thrown in case fingerprint could not be computed.
     * @throws CryptoProviderException Thrown in case cryptography provider is initialized incorrectly.
     */
    public static String compute(ECPublicKey devicePublicKey, ECPublicKey serverPublicKey, String activationId, ActivationVersion activationVersion) throws GenericCryptoException, CryptoProviderException {
        if (devicePublicKey == null) {
            throw new GenericCryptoException("Device public key is invalid");
        }
        try {
            // Prepare fingerprint data
            byte[] fingerprintData;
            switch (activationVersion) {
                case VERSION_2 ->
                    // In version 2 the activation fingerprint is computed from device public key bytes
                        fingerprintData = toByteArray(devicePublicKey);
                case VERSION_3 -> {
                    if (serverPublicKey == null) {
                        throw new GenericCryptoException("Server public key is invalid");
                    }
                    if (activationId == null) {
                        throw new GenericCryptoException("Activation ID is invalid");
                    }
                    // In version 3 the activation fingerprint is computed as devicePublicKeyBytes + activationIdBytes + serverPublicKeyBytes
                    byte[] devicePublicKeyBytes = toByteArray(devicePublicKey);
                    byte[] activationIdBytes = activationId.getBytes(StandardCharsets.UTF_8);
                    byte[] serverPublicKeyBytes = toByteArray(serverPublicKey);
                    ByteBuffer dataBuffer = ByteBuffer.allocate(devicePublicKeyBytes.length + activationIdBytes.length + serverPublicKeyBytes.length);
                    dataBuffer.put(devicePublicKeyBytes);
                    dataBuffer.put(activationIdBytes);
                    dataBuffer.put(serverPublicKeyBytes);
                    fingerprintData = dataBuffer.array();
                }
                default -> throw new GenericCryptoException("Unsupported activation version: " + activationVersion);
            }

            // Calculate fingerprint
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(fingerprintData);
            if (hash.length < 4) { // assert
                throw new GenericCryptoException("Invalid digest");
            }
            int index = hash.length - 4;
            int number = (ByteBuffer.wrap(hash).getInt(index) & 0x7FFFFFFF) % (int) (Math.pow(10, PowerAuthConfiguration.FINGERPRINT_LENGTH));
            return String.format("%0" + PowerAuthConfiguration.FINGERPRINT_LENGTH + "d", number);
        } catch (NoSuchAlgorithmException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new CryptoProviderException(ex.getMessage(), ex);
        }
    }

    /**
     * Convert EC public key to byte array.
     *
     * @param publicKey EC public key.
     * @return Byte array representation of public key.
     */
    private static byte[] toByteArray(ECPublicKey publicKey) {
        byte[] publicKeyBytes = publicKey.getW().getAffineX().toByteArray();
        // Handle case when first byte in BigInteger representation is negative
        // See method BigIntegers.asUnsignedByteArray(BigInteger) in the Bouncy Castle library
        if (publicKeyBytes[0] == 0x00) {
            publicKeyBytes = Arrays.copyOfRange(publicKeyBytes, 1, publicKeyBytes.length);
        }
        return publicKeyBytes;
    }
}
