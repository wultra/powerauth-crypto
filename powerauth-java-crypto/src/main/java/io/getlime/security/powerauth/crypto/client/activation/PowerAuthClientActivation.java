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
package io.getlime.security.powerauth.crypto.client.activation;

import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.crypto.lib.model.ActivationVersion;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.*;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;

/**
 * Class implementing a cryptography used on the client side in order
 * to complete the PowerAuth Client activation.
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthClientActivation {

    private final SignatureUtils signatureUtils = new SignatureUtils();
    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Verify the signature of activation code using Master Public Key.
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
        return signatureUtils.validateECDSASignature(bytes, signature, masterPublicKey);
    }

    /**
     * Generate a device related activation key pair.
     *
     * @return A new device key pair.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public KeyPair generateDeviceKeyPair() throws CryptoProviderException {
        return keyGenerator.generateKeyPair();
    }

    /**
     * Generate a new activation nonce.
     *
     * @return A new activation nonce.
     * @throws CryptoProviderException In case key cryptography provider is incorrectly initialized.
     */
    public byte[] generateActivationNonce() throws CryptoProviderException {
        return keyGenerator.generateRandomBytes(16);
    }


    /**
     * Verify signature of the encrypted activation ID and server public key
     * using a Master Public Key.
     *
     * @param activationId Activation ID
     * @param C_serverPublicKey Encrypted server public key.
     * @param signature Encrypted server public key signature.
     * @param masterPublicKey Master Public Key.
     * @return Returns "true" if signature matches encrypted data, "false" otherwise.
     * @throws InvalidKeyException If provided master public key is invalid.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean verifyServerDataSignature(String activationId, byte[] C_serverPublicKey, byte[] signature, PublicKey masterPublicKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        byte[] activationIdBytes = activationId.getBytes(StandardCharsets.UTF_8);
        String activationIdBytesBase64 = Base64.getEncoder().encodeToString(activationIdBytes);
        String C_serverPublicKeyBase64 = Base64.getEncoder().encodeToString(C_serverPublicKey);
        byte[] result = (activationIdBytesBase64 + "&" + C_serverPublicKeyBase64).getBytes(StandardCharsets.UTF_8);
        return signatureUtils.validateECDSASignature(result, signature, masterPublicKey);
    }

    /**
     * Compute a fingerprint for the version 3 activation. The fingerprint can be used for visual validation of exchanged device public key.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
     *     <li>3.1</li>
     *     <li>3.2</li>
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

        // Prepare objects to read status info into
        ActivationStatusBlobInfo statusInfo = new ActivationStatusBlobInfo();
        ByteBuffer buffer = ByteBuffer.wrap(statusBlob);

        // check if the prefix is OK
        int prefix = buffer.getInt(0);
        statusInfo.setValid(prefix == ActivationStatusBlobInfo.ACTIVATION_STATUS_MAGIC_VALUE);

        // fetch the activation status byte
        statusInfo.setActivationStatus(buffer.get(4));

        // fetch the current version status byte
        statusInfo.setCurrentVersion(buffer.get(5));

        // fetch the upgrade version status byte
        statusInfo.setUpgradeVersion(buffer.get(6));

        // fetch ctr byte value
        statusInfo.setCtrByte(buffer.get(12));

        // fetch the failed attempt count
        statusInfo.setFailedAttempts(buffer.get(13));

        // fetch the max allowed failed attempt count
        statusInfo.setMaxFailedAttempts(buffer.get(14));

        // fetch counter's look ahead window value
        statusInfo.setCtrLookAhead(buffer.get(15));

        // extract counter data from second half of status blob
        byte[] ctrData = Arrays.copyOfRange(statusBlob, 16, 32);
        statusInfo.setCtrDataHash(ctrData);

        return statusInfo;
    }

    /**
     * Verify whether client's value of hash based counter is equal to the value received from the server. The value
     * received from the server is already hashed, so the function has to calculate hash from the client's counter
     * and then compare both values.
     *
     * @param receivedCtrDataHash Value received from the server, containing hash, calculated from hash based counter.
     * @param expectedCtrData Expected hash based counter.
     * @param transportKey Transport key.
     * @return {@code true} in case that received hash equals to hash calculated from counter data.
     * @throws InvalidKeyException When invalid key is provided.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean verifyHashForHashBasedCounter(byte[] receivedCtrDataHash, byte[] expectedCtrData, SecretKey transportKey)
            throws CryptoProviderException, InvalidKeyException, GenericCryptoException {
        return new HashBasedCounterUtils().verifyHashForHashBasedCounter(receivedCtrDataHash, expectedCtrData, transportKey);
    }
}
