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
package com.wultra.security.powerauth.crypto.client.activation;

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
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * Class implementing a cryptography used on the client side in order
 * to complete the PowerAuth Client activation.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthClientActivation {

    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();
    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();

    /**
     * Generate a device related activation key pair.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @return A new device key pair.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public KeyPair generateDeviceKeyPair() throws CryptoProviderException {
        return KEY_GENERATOR.generateKeyPair(EcCurve.P256);
    }

    /**
     * Verify the signature of activation code using Master Public Key.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param activationCode Activation code.
     * @param signature Activation data signature.
     * @param masterPublicKey Master Public Key.
     * @return Returns "true" if the signature matches activation data, "false" otherwise.
     * @throws InvalidKeyException If provided master public key is invalid.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean verifyActivationCodeSignature(String activationCode, byte[] signature, PublicKey masterPublicKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        byte[] bytes = activationCode.getBytes(StandardCharsets.UTF_8);
        return SIGNATURE_UTILS.validateECDSASignature(EcCurve.P256, bytes, signature, masterPublicKey);
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
     * @param activationVersion Activation version.
     * @return Fingerprint of the public keys.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws GenericCryptoException In case fingerprint could not be calculated.
     */
    public String computeActivationFingerprint(PublicKey devicePublicKey, PublicKey serverPublicKey, String activationId, ActivationVersion activationVersion) throws GenericCryptoException, CryptoProviderException {
        return ECPublicKeyFingerprint.compute(((ECPublicKey)devicePublicKey), (ECPublicKey)serverPublicKey, activationId, activationVersion);
    }

    /**
     * Returns an activation status from the encrypted activation blob as described in PowerAuth Specification.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
     * </ul>
     *
     * @param cStatusBlob Encrypted activation status blob.
     * @param challenge Challenge for activation status blob encryption. If non-null, then also {@code nonce} parameter must be provided.
     * @param nonce Nonce for activation status blob encryption. If non-null, then also {@code challenge} parameter must be provided.
     * @param transportKey A key used to protect the transport.
     * @return Status information from the status blob.
     * @throws InvalidKeyException When invalid key is provided.
     * @throws GenericCryptoException In case decryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public ActivationStatusBlobInfo getStatusFromEncryptedBlob(byte[] cStatusBlob, byte[] challenge, byte[] nonce, SecretKey transportKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        if (cStatusBlob.length != 32) {
            throw new GenericCryptoException("Invalid status blob size");
        }

        // Decrypt the status blob
        AESEncryptionUtils aes = new AESEncryptionUtils();
        byte[] iv = new KeyDerivationUtils().deriveIvForStatusBlobEncryption(challenge, nonce, transportKey);
        byte[] statusBlob = aes.decrypt(cStatusBlob, iv, transportKey, "AES/CBC/NoPadding");
        return getStatusFromBlob(statusBlob);
    }

    /**
     * Returns an activation status from the activation blob as described in PowerAuth Specification.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
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
        statusInfo.setValid(prefix == ActivationStatusBlobInfo.ACTIVATION_STATUS_MAGIC_VALUE_V3 || prefix == ActivationStatusBlobInfo.ACTIVATION_STATUS_MAGIC_VALUE_V4);

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
     * Verify whether client's value of hash based counter is equal to the value received from the server. The value
     * received from the server is already hashed, so the function has to calculate hash from the client's counter
     * and then compare both values.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
     *     <li>3.3</li>
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
        return new HashBasedCounterUtils().verifyHashForHashBasedCounter(receivedCtrDataHash, expectedCtrData, transportKey, protocolVersion);
    }

}
