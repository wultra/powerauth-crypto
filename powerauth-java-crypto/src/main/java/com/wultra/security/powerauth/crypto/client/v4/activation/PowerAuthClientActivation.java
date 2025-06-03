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
package com.wultra.security.powerauth.crypto.client.v4.activation;

import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.enums.ProtocolVersion;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.*;
import com.wultra.security.powerauth.crypto.lib.v4.PqcDsa;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.CustomString;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.Kmac;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Class implementing a cryptography used on the client side in order
 * to complete the PowerAuth Client activation (V4).
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthClientActivation {

    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();
    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final PqcDsa PQC_DSA = new PqcDsa();

    /**
     * Custom bytes for MAC for counter data.
     */
    private static final byte[] KMAC_STATUS_CUSTOM_BYTES = CustomString.PA4MAC_STATUS.value().getBytes(StandardCharsets.UTF_8);

    /**
     * Generate a device related EC key pair.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @return A new device EC key pair.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public KeyPair generateDeviceEcKeyPair() throws CryptoProviderException {
        return KEY_GENERATOR.generateKeyPair(EcCurve.P384);
    }

    /**
     * Generate a device related PQC DSA key pair.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @return A new device PQC key pair.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public KeyPair generateDevicePqcKeyPair() throws CryptoProviderException {
        return PQC_DSA.generateKeyPair();
    }

    /**
     * Verify the EC activation code signature.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param activationCode Activation code.
     * @param signature Activation data EC signature.
     * @param masterPublicKey Master Public Key.
     * @return Returns true if the signature matches activation data, false otherwise.
     * @throws InvalidKeyException If provided master public key is invalid.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean verifyActivationCodeEcSignature(String activationCode, byte[] signature, PublicKey masterPublicKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        final byte[] bytes = activationCode.getBytes(StandardCharsets.UTF_8);
        return SIGNATURE_UTILS.validateECDSASignature(EcCurve.P384, bytes, signature, masterPublicKey);
    }

    /**
     * Verify the PQC activation code signature.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param activationCode Activation code.
     * @param signature Activation data PQC signature.
     * @param masterPublicKey Master Public Key.
     * @return Returns true if the signature matches activation data, false otherwise.
     * @throws InvalidKeyException If provided master public key is invalid.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean verifyActivationCodePqcSignature(String activationCode, byte[] signature, PublicKey masterPublicKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        final byte[] bytes = activationCode.getBytes(StandardCharsets.UTF_8);
        return PQC_DSA.verify(masterPublicKey, bytes, signature);
    }

    /**
     * Compute a fingerprint for the version 4 activation for algorithm EC_P384. The fingerprint can be used for visual validation of exchanged device public key.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param devicePublicKey Device public key.
     * @param serverPublicKey Server public key.
     * @param activationId Activation ID.
     * @return Fingerprint of the public key.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws GenericCryptoException In case fingerprint could not be calculated.
     */
    public String computeActivationEcFingerprint(PublicKey devicePublicKey, PublicKey serverPublicKey, String activationId) throws GenericCryptoException, CryptoProviderException {
        // TODO - support for crypto4
        return "";
    }

    /**
     * Compute a fingerprint for the version 4 activation for algorithm EC_P384_ML_L3. The fingerprint can be used for visual validation of exchanged device public key.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param ecDevicePublicKey EC device public key.
     * @param pqcDevicePublicKey PQC device public key.
     * @param ecServerPublicKey EC server public key.
     * @param pqcServerPublicKey PQC server public key.
     * @param activationId Activation ID.
     * @return Fingerprint of the public keys.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws GenericCryptoException In case fingerprint could not be calculated.
     */
    public String computeActivationHybridFingerprint(PublicKey ecDevicePublicKey, PublicKey pqcDevicePublicKey, PublicKey ecServerPublicKey, PublicKey pqcServerPublicKey, String activationId) throws GenericCryptoException, CryptoProviderException {
        // TODO - support for crypto4
        return "";
    }

    /**
     * Returns an activation status from the activation blob as described in PowerAuth Specification.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param statusBlob Activation status blob.
     * @return Status information from the status blob.
     */
    public ActivationStatusBlobInfo getStatusFromBlob(byte[] statusBlob) {
        // Prepare objects to read status info into
        ActivationStatusBlobInfo statusInfo = new ActivationStatusBlobInfo();
        ByteBuffer buffer = ByteBuffer.wrap(statusBlob);

        // check if the prefix is OK
        int prefix = buffer.getInt(0);
        statusInfo.setValid(prefix == ActivationStatusBlobInfo.ACTIVATION_STATUS_MAGIC_VALUE_V4);

        // fetch the activation status byte
        statusInfo.setActivationStatus(buffer.get(4));

        // fetch the current version status byte
        statusInfo.setCurrentVersion(buffer.get(5));

        // fetch the upgrade version status byte
        statusInfo.setUpgradeVersion(buffer.get(6));

        // fetch the status flags
        statusInfo.setStatusFlags(buffer.get(7));

        // fetch ctr byte value
        statusInfo.setCtrByte(buffer.get(12));

        // fetch the failed attempt count
        statusInfo.setFailedAttempts(buffer.get(13));

        // fetch the max allowed failed attempt count
        statusInfo.setMaxFailedAttempts(buffer.get(14));

        // fetch counter's look ahead window value
        statusInfo.setCtrLookAhead(buffer.get(15));

        // extract counter data from second half of status blob
        byte[] ctrData = Arrays.copyOfRange(statusBlob, 16, statusBlob.length);
        statusInfo.setCtrDataHash(ctrData);

        return statusInfo;
    }

    /**
     * Verify MAC for activation status.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param statusData Activation status data.
     * @param expectedStatusMac Expected status MAC.
     * @param keyCtrStatusMac Key for calculating MAC for activation data.
     * @param protocolVersion Protocol version.
     * @return Activation status MAC.
     * @throws GenericCryptoException In case of a cryptography error.
     */
    public boolean verifyStatusMac(byte[] statusData, byte[] expectedStatusMac, SecretKey keyCtrStatusMac, ProtocolVersion protocolVersion) throws GenericCryptoException {
        if (protocolVersion.getMajorVersion() != 4) {
            throw new GenericCryptoException("Unsupported protocol version: " + protocolVersion);
        }
        return SideChannelUtils.constantTimeAreEqual(expectedStatusMac, Kmac.kmac256(keyCtrStatusMac, statusData, KMAC_STATUS_CUSTOM_BYTES));
    }

    /**
     * Verify whether client's value of hash based counter is equal to the value received from the server. The value
     * received from the server is already hashed, so the function has to calculate hash from the client's counter
     * and then compare both values.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param receivedCtrDataHash Value received from the server, containing hash, calculated from hash based counter.
     * @param expectedCtrData Expected hash based counter.
     * @param transportKey Transport key.
     * @param protocolVersion Protocol version.
     * @return {@code true} in case that received hash equals to hash calculated from counter data.
     * @throws InvalidKeyException When invalid key is provided.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean verifyHashForHashBasedCounter(byte[] receivedCtrDataHash, byte[] expectedCtrData, SecretKey transportKey, ProtocolVersion protocolVersion)
            throws CryptoProviderException, InvalidKeyException, GenericCryptoException {
        if (protocolVersion.getMajorVersion() != 4) {
            throw new GenericCryptoException("Unsupported protocol version: " + protocolVersion);
        }
        return new HashBasedCounterUtils().verifyHashForHashBasedCounter(receivedCtrDataHash, expectedCtrData, transportKey, protocolVersion);
    }

}
