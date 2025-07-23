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
package com.wultra.security.powerauth.crypto.server.activation;

import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.enums.ProtocolVersion;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import com.wultra.security.powerauth.crypto.lib.model.ActivationVersion;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.*;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * Class implementing cryptography used on a server side in order to assure
 * PowerAuth Server activation related processes (V3).
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 *     <li>3.3</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthServerActivation {

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();

    /**
     * Generate a server related activation key pair.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @return A new server key pair.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public KeyPair generateServerKeyPair() throws CryptoProviderException {
        return KEY_GENERATOR.generateKeyPair(EcCurve.P256);
    }

    /**
     * Generate signature for the activation code.
     * <p>
     * Signature is then computed using the master private key.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param activationCode Short activation ID.
     * @param masterPrivateKey Master Private Key.
     * @return Signature of activation data using Master Private Key.
     * @throws InvalidKeyException In case Master Private Key is invalid.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] generateActivationSignature(String activationCode,
                                              PrivateKey masterPrivateKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        byte[] bytes = activationCode.getBytes(StandardCharsets.UTF_8);
        return SIGNATURE_UTILS.computeECDSASignature(EcCurve.P256, bytes, masterPrivateKey);
    }



    /**
     * Compute a fingerprint for the version 3 activation. The fingerprint can be used for visual validation of exchanged device public key.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param devicePublicKey Device public key.
     * @param serverPublicKey Server public key.
     * @param activationId Activation ID.
     * @return Fingerprint of the public key.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws GenericCryptoException In case fingerprint could not be calculated.
     */
    public String computeActivationFingerprint(PublicKey devicePublicKey, PublicKey serverPublicKey, String activationId) throws GenericCryptoException, CryptoProviderException {
        return computeActivationFingerprint(devicePublicKey, serverPublicKey, activationId, ActivationVersion.VERSION_3);
    }

    /**
     * Compute a fingerprint for the activation. The fingerprint can be used for visual validation of exchanged public keys.
     *
     * @param devicePublicKey Device public key.
     * @param serverPublicKey Server public key.
     * @param activationId Activation ID.
     * @param activationVersion Activation version.
     * @return Fingerprint of the public key.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws GenericCryptoException In case fingerprint could not be calculated.
     */
    public String computeActivationFingerprint(PublicKey devicePublicKey, PublicKey serverPublicKey, String activationId, ActivationVersion activationVersion) throws GenericCryptoException, CryptoProviderException {
        return ECPublicKeyFingerprint.compute(((ECPublicKey)devicePublicKey), (ECPublicKey)serverPublicKey, activationId, activationVersion);
    }

    /**
     * Returns an encrypted status blob as described in PowerAuth Specification.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param statusBlobInfo {@link ActivationStatusBlobInfo} object with activation status data to be encrypted.
     * @param challenge Challenge for activation status blob encryption. If non-null, then also {@code nonce} parameter must be provided.
     * @param nonce Nonce for activation status blob encryption. If non-null, then also {@code challenge} parameter must be provided.
     * @param transportKey A key used to protect the transport.
     * @param protocolVersion Protocol version.
     * @return Encrypted status blob
     * @throws InvalidKeyException When invalid key is provided.
     * @throws GenericCryptoException In case encryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] encryptedStatusBlob(ActivationStatusBlobInfo statusBlobInfo, byte[] challenge, byte[] nonce, SecretKey transportKey, ProtocolVersion protocolVersion)
            throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        // Validate inputs
        if (statusBlobInfo == null) {
            throw new GenericCryptoException("Required statusBlobInfo parameter is missing");
        }
        if (transportKey == null) {
            throw new GenericCryptoException("Required transportKey parameter is missing");
        }
        final byte[] statusBlob = generateStatusBlob(statusBlobInfo, protocolVersion);

        // Derive IV and encrypt status blob data.
        final byte[] iv = new KeyDerivationUtils().deriveIvForStatusBlobEncryption(challenge, nonce, transportKey);
        return new AESEncryptionUtils().encrypt(statusBlob, iv, transportKey, "AES/CBC/NoPadding");
    }

    /**
     * Generate activations status blob for different protocol versions.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param statusBlobInfo Activation status blog information.
     * @param protocolVersion Protocol version.
     * @return Status blob byte array.
     * @throws GenericCryptoException In case encryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] generateStatusBlob(ActivationStatusBlobInfo statusBlobInfo, ProtocolVersion protocolVersion) throws GenericCryptoException, CryptoProviderException {
        final byte[] ctrDataHash;
        final byte ctrByte;
        final byte ctrLookAhead;
        final int magicValue;
        final byte[] statusFlagsAndReserved;
        final int blobLength;
        if (protocolVersion.getMajorVersion() != 3) {
            throw new GenericCryptoException("Unsupported protocol version: " + protocolVersion);
        } else if (protocolVersion != ProtocolVersion.V30) {
            if (statusBlobInfo.getCtrDataHash() == null) {
                throw new GenericCryptoException("Missing ctrDataHash in statusBlobInfo object");
            }
            magicValue = ActivationStatusBlobInfo.ACTIVATION_STATUS_MAGIC_VALUE_V3;
            // Reserved 5 bytes
            statusFlagsAndReserved = KEY_GENERATOR.generateRandomBytes(5);
            ctrDataHash = statusBlobInfo.getCtrDataHash();
            ctrByte = statusBlobInfo.getCtrByte();
            ctrLookAhead = statusBlobInfo.getCtrLookAhead();
            blobLength = 32;
        } else {
            // Legacy protocol version (3.0)
            //
            // In this case, ctrDataHash, ctrInfo, ctrLookAhead should be completely random values, because
            // mobile clients don't use them. The older protocols also use zero-IV for the encryption, so the first
            // block encrypted by AES should have as much entropy as possible.
            //
            magicValue = ActivationStatusBlobInfo.ACTIVATION_STATUS_MAGIC_VALUE_V3;
            final byte[] randomBytes = KEY_GENERATOR.generateRandomBytes(5 + 2 + 16);
            // Reserved 5 bytes
            statusFlagsAndReserved = Arrays.copyOf(randomBytes, 5);
            ctrDataHash = Arrays.copyOfRange(randomBytes, 5 + 2, 5 + 2 + 16);
            ctrByte = randomBytes[5];
            ctrLookAhead = randomBytes[6];
            blobLength = 32;
        }
        return ByteBuffer.allocate(blobLength)
                .putInt(magicValue)                          // 4 bytes
                .put(statusBlobInfo.getActivationStatus())   // 1 byte
                .put(statusBlobInfo.getCurrentVersion())     // 1 byte
                .put(statusBlobInfo.getUpgradeVersion())     // 1 byte
                .put(statusFlagsAndReserved)                 // 5 bytes
                .put(ctrByte)                                // 1 byte
                .put(statusBlobInfo.getFailedAttempts())     // 1 byte
                .put(statusBlobInfo.getMaxFailedAttempts())  // 1 byte
                .put(ctrLookAhead)                           // 1 byte
                .put(ctrDataHash)                            // 16 bytes
                .array();
    }

    /**
     * Calculate hash from value representing the hash based counter. HMAC-SHA256 is currently used as a hashing
     * function.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param ctrData Hash-based counter.
     * @param keyCtrDataMac Key for calculating the counter data hash.
     * @param protocolVersion Protocol version.
     * @return Hash calculated from provided hash-based counter.
     * @throws GenericCryptoException In case that key derivation fails or you provided invalid ctrData.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws InvalidKeyException In case that transport key is not valid.
     */
    public byte[] calculateHashFromHashBasedCounter(byte[] ctrData, SecretKey keyCtrDataMac, ProtocolVersion protocolVersion)
            throws CryptoProviderException, InvalidKeyException, GenericCryptoException {
        if (protocolVersion.getMajorVersion() != 3) {
            throw new GenericCryptoException("Unsupported protocol version: " + protocolVersion);
        }
        return new HashBasedCounterUtils().calculateHashFromHashBasedCounter(ctrData, keyCtrDataMac, protocolVersion);
    }

}
