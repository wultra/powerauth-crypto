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
package com.wultra.security.powerauth.crypto.lib.util;

import com.wultra.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import com.wultra.security.powerauth.crypto.lib.model.ActivationVersion;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.hash.Sha3;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * Class that is used for computing public key fingerprint for algorithms EC_P384 and EC_P384_ML_*.
 * The goal of the public key fingerprint is to enable user to visually check that the public key was
 * successfully exchanged between client and server.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class HybridPublicKeyFingerprint {

    /**
     * Compute activation fingerprint for ECDSA.
     * @param devicePublicKey EC device public key.
     * @param serverPublicKey EC server public key.
     * @param activationId Activation ID.
     * @param activationVersion Activation version.
     * @return Fingerprint of the public keys.
     * @throws GenericCryptoException In case fingerprint could not be calculated.
     */
    public static String computeEcdsaFingerprint(ECPublicKey devicePublicKey, ECPublicKey serverPublicKey, String activationId, ActivationVersion activationVersion) throws GenericCryptoException {
        if (activationVersion != ActivationVersion.VERSION_4) {
            throw new GenericCryptoException("Unsupported activation version: " + activationVersion);
        }
        return computeEcP384Fingerprint(devicePublicKey, serverPublicKey, activationId);
    }

    /**
     * Compute activation fingerprint for ECDSA or hybrid ECDSA + ML-DSA.
     *
     * @param sharedSecretAlgorithm Shared secret algorithm.
     * @param ecDevicePublicKey EC device public key.
     * @param pqcDevicePublicKey PQC device public key.
     * @param ecServerPublicKey EC server public key.
     * @param pqcServerPublicKey PQC server public key.
     * @param activationId Activation ID.
     * @param activationVersion Activation version.
     * @return Fingerprint of the public keys.
     * @throws GenericCryptoException In case fingerprint could not be calculated.
     */
    public static String computeHybridFingerprint(SharedSecretAlgorithm sharedSecretAlgorithm, ECPublicKey ecDevicePublicKey, MLDSAPublicKey pqcDevicePublicKey, ECPublicKey ecServerPublicKey, MLDSAPublicKey pqcServerPublicKey, String activationId, ActivationVersion activationVersion) throws GenericCryptoException {
        if (activationVersion != ActivationVersion.VERSION_4) {
            throw new GenericCryptoException("Unsupported activation version: " + activationVersion);
        }
        return computeEcP384MlFingerprint(sharedSecretAlgorithm, ecDevicePublicKey, pqcDevicePublicKey, ecServerPublicKey, pqcServerPublicKey, activationId);
    }

    private static String computeEcP384Fingerprint(ECPublicKey ecDevicePublicKey, ECPublicKey ecServerPublicKey, String activationId) throws GenericCryptoException {
        if (ecDevicePublicKey == null || ecServerPublicKey == null || activationId == null) {
            throw new GenericCryptoException("Missing data for EC_P384 fingerprint computation");
        }
        final byte[] fingerprintBytes = ByteUtils.concat(
                SharedSecretAlgorithm.EC_P384.name().getBytes(StandardCharsets.UTF_8),
                getNormalizedPublicKeyBytes(ecDevicePublicKey),
                activationId.getBytes(StandardCharsets.UTF_8),
                getNormalizedPublicKeyBytes(ecServerPublicKey)
        );
        return computeTruncatedFingerprint(fingerprintBytes);
    }

    private static String computeEcP384MlFingerprint(SharedSecretAlgorithm sharedSecretAlgorithm, ECPublicKey ecDevicePublicKey, MLDSAPublicKey pqcDevicePublicKey, ECPublicKey ecServerPublicKey, MLDSAPublicKey pqcServerPublicKey, String activationId) throws GenericCryptoException {
        if (ecDevicePublicKey == null || pqcDevicePublicKey == null || ecServerPublicKey == null || pqcServerPublicKey == null || activationId == null) {
            throw new GenericCryptoException("Missing data for hybrid fingerprint computation");
        }
        if (sharedSecretAlgorithm != SharedSecretAlgorithm.EC_P384_ML_L3 && sharedSecretAlgorithm != SharedSecretAlgorithm.EC_P384_ML_L5) {
            throw new GenericCryptoException("Hybrid shared secret algorithm expected for fingerprint, requested algorithm: " + sharedSecretAlgorithm);
        }
        final byte[] fingerprintBytes = ByteUtils.concat(
                sharedSecretAlgorithm.name().getBytes(StandardCharsets.UTF_8),
                getNormalizedPublicKeyBytes(ecDevicePublicKey),
                getNormalizedPublicKeyBytes(pqcDevicePublicKey),
                activationId.getBytes(StandardCharsets.UTF_8),
                getNormalizedPublicKeyBytes(ecServerPublicKey),
                getNormalizedPublicKeyBytes(pqcServerPublicKey)
        );
        return computeTruncatedFingerprint(fingerprintBytes);
    }

    private static String computeTruncatedFingerprint(byte[] fingerprintBytes) throws GenericCryptoException {
        byte[] hash = Sha3.hash256(fingerprintBytes);
        if (hash.length < 4) {
            throw new GenericCryptoException("Invalid digest");
        }
        final int index = hash.length - 4;
        final int number = (ByteBuffer.wrap(hash).getInt(index) & 0x7FFFFFFF) % (int) (Math.pow(10, PowerAuthConfiguration.FINGERPRINT_LENGTH));
        return String.format("%0" + PowerAuthConfiguration.FINGERPRINT_LENGTH + "d", number);
    }

    private static byte[] getNormalizedPublicKeyBytes(ECPublicKey publicKey) {
        byte[] publicKeyBytes = publicKey.getW().getAffineX().toByteArray();
        // Handle case when first byte in BigInteger representation is negative
        // See method BigIntegers.asUnsignedByteArray(BigInteger) in the Bouncy Castle library
        if (publicKeyBytes[0] == 0x00) {
            publicKeyBytes = Arrays.copyOfRange(publicKeyBytes, 1, publicKeyBytes.length);
        }
        return publicKeyBytes;
    }

    private static byte[] getNormalizedPublicKeyBytes(MLDSAPublicKey publicKey) {
        return publicKey.getEncoded();
    }

}
