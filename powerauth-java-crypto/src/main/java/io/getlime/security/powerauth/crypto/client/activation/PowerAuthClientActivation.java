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

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.crypto.lib.util.ECPublicKeyFingerprint;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import io.getlime.security.powerauth.provider.exception.CryptoProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Class implementing a cryptography used on the client side in order
 * to complete the PowerAuth Client activation.
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthClientActivation {

    private final SignatureUtils signatureUtils = new SignatureUtils();

    /**
     * Verify the signature of activation code using Master Public Key.
     *
     * @param activationCode Activation code.
     * @param signature Activation data signature.
     * @param masterPublicKey Master Public Key.
     * @return Returns "true" if the signature matches activation data, "false" otherwise.
     * @throws InvalidKeyException If provided master public key is invalid.
     * @throws GenericCryptoException In case signature computation fails.
     */
    public boolean verifyActivationCodeSignature(String activationCode, byte[] signature, PublicKey masterPublicKey) throws InvalidKeyException, GenericCryptoException {
        try {
            byte[] bytes = activationCode.getBytes(StandardCharsets.UTF_8);
            return signatureUtils.validateECDSASignature(bytes, signature, masterPublicKey);
        } catch (SignatureException ex) {
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Generate a device related activation key pair.
     *
     * @return A new device key pair.
     * @throws GenericCryptoException In case cryptography provider is incorrectly initialized.
     */
    public KeyPair generateDeviceKeyPair() throws GenericCryptoException {
        return new KeyGenerator().generateKeyPair();
    }

    /**
     * Generate a new activation nonce.
     *
     * @return A new activation nonce.
     */
    public byte[] generateActivationNonce() {
        return new KeyGenerator().generateRandomBytes(16);
    }

    /**
     * Method computes the signature of the activation data in order to prove that a correct
     * client application is attempting to complete the activation.
     *
     * <h5>PowerAuth protocol versions:</h5>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * This method is obsolete for PowerAuth protocol version 3.0 and will be deprecated in a future release.
     *
     * @param activationIdShort Short activation ID.
     * @param activationNonce Client activation nonce.
     * @param encryptedDevicePublicKey Encrypted device public key.
     * @param applicationKey Application identifier.
     * @param applicationSecret Application secret.
     * @return Signature bytes.
     * @throws GenericCryptoException In case hash computation fails.
     */
    public byte[] computeApplicationSignature(String activationIdShort, byte[] activationNonce, byte[] encryptedDevicePublicKey, byte[] applicationKey, byte[] applicationSecret) throws GenericCryptoException {
        String signatureBaseString = activationIdShort + "&"
                + BaseEncoding.base64().encode(activationNonce) + "&"
                + BaseEncoding.base64().encode(encryptedDevicePublicKey) + "&"
                + BaseEncoding.base64().encode(applicationKey);
        return new HMACHashUtilities().hash(applicationSecret, signatureBaseString.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Encrypt a device public key using the activation OTP.
     *
     * <h5>PowerAuth protocol versions:</h5>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * @param devicePublicKey Device public key to be encrypted.
     * @param clientEphemeralPrivateKey Ephemeral private key.
     * @param masterPublicKey Master public key.
     * @param activationOTP Activation OTP value.
     * @param activationIdShort Short activation ID.
     * @param activationNonce Activation nonce, used as an initialization vector for AES encryption.
     * @return An encrypted device public key.
     * @throws InvalidKeyException In case provided public key is invalid.
     * @throws GenericCryptoException In case encryption fails.
     */
    public byte[] encryptDevicePublicKey(PublicKey devicePublicKey, PrivateKey clientEphemeralPrivateKey, PublicKey masterPublicKey, String activationOTP, String activationIdShort, byte[] activationNonce) throws InvalidKeyException, GenericCryptoException {
        try {
            KeyGenerator keyGenerator = new KeyGenerator();
            byte[] activationIdShortBytes = activationIdShort.getBytes(StandardCharsets.UTF_8);
            SecretKey otpBasedSymmetricKey = keyGenerator.deriveSecretKeyFromPassword(activationOTP, activationIdShortBytes);
            byte[] devicePubKeyBytes = PowerAuthConfiguration.INSTANCE.getKeyConvertor().convertPublicKeyToBytes(devicePublicKey);
            SecretKey ephemeralKey = keyGenerator.computeSharedKey(clientEphemeralPrivateKey, masterPublicKey);
            AESEncryptionUtils aes = new AESEncryptionUtils();
            byte[] tmpData = aes.encrypt(devicePubKeyBytes, activationNonce, otpBasedSymmetricKey);
            return aes.encrypt(tmpData, activationNonce, ephemeralKey);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
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
     */
    public boolean verifyServerDataSignature(String activationId, byte[] C_serverPublicKey, byte[] signature, PublicKey masterPublicKey) throws InvalidKeyException, GenericCryptoException {
        try {
            byte[] activationIdBytes = activationId.getBytes(StandardCharsets.UTF_8);
            String activationIdBytesBase64 = BaseEncoding.base64().encode(activationIdBytes);
            String C_serverPublicKeyBase64 = BaseEncoding.base64().encode(C_serverPublicKey);
            byte[] result = (activationIdBytesBase64 + "&" + C_serverPublicKeyBase64).getBytes(StandardCharsets.UTF_8);
            return signatureUtils.validateECDSASignature(result, signature, masterPublicKey);
        } catch (SignatureException ex) {
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Decrypt server public key using activation OTP and device private key. As a technical component for public key encryption, an ephemeral public key is
     * used (in order to deduce ephemeral symmetric key using ECDH).
     *
     * <h5>PowerAuth protocol versions:</h5>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * @param C_serverPublicKey Encrypted server public key.
     * @param devicePrivateKey Device private key.
     * @param ephemeralPublicKey Ephemeral public key.
     * @param activationOTP Activation OTP value.
     * @param activationIdShort Short activation OTP.
     * @param activationNonce Activation nonce, used as an initialization vector for AES encryption.
     * @return Decrypted server public key.
     * @throws InvalidKeyException In case some of the provided keys is invalid.
     * @throws GenericCryptoException In case decryption fails.
     */
    public PublicKey decryptServerPublicKey(byte[] C_serverPublicKey, PrivateKey devicePrivateKey, PublicKey ephemeralPublicKey, String activationOTP, String activationIdShort, byte[] activationNonce) throws InvalidKeyException, GenericCryptoException {

        try {
            KeyGenerator keyGenerator = new KeyGenerator();
            SecretKey ephemeralSymmetricKey = keyGenerator.computeSharedKey(devicePrivateKey, ephemeralPublicKey);

            byte[] activationIdShortBytes = activationIdShort.getBytes(StandardCharsets.UTF_8);
            SecretKey otpBasedSymmetricKey = keyGenerator.deriveSecretKeyFromPassword(activationOTP, activationIdShortBytes);

            AESEncryptionUtils aes = new AESEncryptionUtils();
            byte[] decryptedTMP = aes.decrypt(C_serverPublicKey, activationNonce, ephemeralSymmetricKey);
            byte[] decryptedServerPublicKeyBytes = aes.decrypt(decryptedTMP, activationNonce, otpBasedSymmetricKey);

            return PowerAuthConfiguration.INSTANCE.getKeyConvertor().convertBytesToPublicKey(decryptedServerPublicKeyBytes);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException | CryptoProviderException ex) {
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Compute a fingerprint of the device public key. The fingerprint can be used for visual validation of an exchanged public key.
     *
     * @param devicePublicKey Public key for computing fingerprint.
     * @return Fingerprint of the public key.
     * @throws GenericCryptoException In case cryptography provider is incorrectly initialized.
     */
    public String computeDevicePublicKeyFingerprint(PublicKey devicePublicKey) throws GenericCryptoException {
        try {
            return ECPublicKeyFingerprint.compute(((ECPublicKey)devicePublicKey));
        } catch (NoSuchAlgorithmException ex) {
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Returns an activation status from the encrypted activation blob as described in PowerAuth Specification.
     *
     * @param cStatusBlob Encrypted activation status blob.
     * @param transportKey A key used to protect the transport.
     * @return Status information from the status blob.
     * @throws InvalidKeyException When invalid key is provided.
     * @throws GenericCryptoException In case decryption fails.
     */
    public ActivationStatusBlobInfo getStatusFromEncryptedBlob(byte[] cStatusBlob, SecretKey transportKey) throws InvalidKeyException, GenericCryptoException {
        try {

            if (cStatusBlob.length != 32) {
                // return mock status in case byte array has weird length
                ActivationStatusBlobInfo statusInfo = new ActivationStatusBlobInfo();
                statusInfo.setActivationStatus((byte) 5);
                statusInfo.setCurrentVersion((byte) 3);
                statusInfo.setUpgradeVersion((byte) 3);
                statusInfo.setFailedAttempts((byte) 0);
                statusInfo.setMaxFailedAttempts((byte) 5);
                statusInfo.setValid(false);
                return statusInfo;
            }

            // Decrypt the status blob
            AESEncryptionUtils aes = new AESEncryptionUtils();
            byte[] zeroIv = new byte[16];
            byte[] statusBlob = aes.decrypt(cStatusBlob, zeroIv, transportKey, "AES/CBC/NoPadding");

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

            // fetch the failed attempt count
            statusInfo.setFailedAttempts(buffer.get(13));

            // fetch the max allowed failed attempt count
            statusInfo.setMaxFailedAttempts(buffer.get(14));

            return statusInfo;
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

}
