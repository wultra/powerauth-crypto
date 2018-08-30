/*
 * Copyright 2016 Wultra s.r.o.
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
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.crypto.lib.util.ECPublicKeyFingerprint;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import io.getlime.security.powerauth.crypto.server.activation.PowerAuthServerActivation;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;

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
     * Verify the signature of activation data using Master Public Key. Signature is computed as the concatenation of activationIdShort and activationOTP,
     * separated with the "-" character:
     *
     * activationData = activationIdShort + "-" + activationOTP
     *
     * @param activationIdShort Short activation ID.
     * @param activationOTP Activation OTP value.
     * @param signature Activation data signature.
     * @param masterPublicKey Master Public Key.
     * @return Returns "true" if the signature matches activation data, "false" otherwise.
     * @throws InvalidKeyException If provided master public key is invalid.
     */
    public boolean verifyActivationDataSignature(String activationIdShort, String activationOTP, byte[] signature, PublicKey masterPublicKey) throws InvalidKeyException {
        try {
            byte[] bytes = (activationIdShort + "-" + activationOTP).getBytes("UTF-8");
            return signatureUtils.validateECDSASignature(bytes, signature, masterPublicKey);
        } catch (SignatureException | UnsupportedEncodingException ex) {
            Logger.getLogger(PowerAuthClientActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    /**
     * Generate a device related activation key pair.
     *
     * @return A new device key pair.
     */
    public KeyPair generateDeviceKeyPair() {
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
     * @param activationIdShort Short activation ID.
     * @param activationNonce Client activation nonce.
     * @param encryptedDevicePublicKey Encrypted device public key.
     * @param applicationKey Application identifier.
     * @param applicationSecret Application secret.
     * @return Signature bytes.
     */
    public byte[] computeApplicationSignature(String activationIdShort, byte[] activationNonce, byte[] encryptedDevicePublicKey, byte[] applicationKey, byte[] applicationSecret) {
        try {
            String signatureBaseString = activationIdShort + "&"
                    + BaseEncoding.base64().encode(activationNonce) + "&"
                    + BaseEncoding.base64().encode(encryptedDevicePublicKey) + "&"
                    + BaseEncoding.base64().encode(applicationKey);
            return new HMACHashUtilities().hash(applicationSecret, signatureBaseString.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(PowerAuthClientActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Encrypt a device public key using the activation OTP.
     *
     * @param devicePublicKey Device public key to be encrypted.
     * @param clientEphemeralPrivateKey Ephemeral private key.
     * @param masterPublicKey Master public key.
     * @param activationOTP Activation OTP value.
     * @param activationIdShort Short activation ID.
     * @param activationNonce Activation nonce, used as an initialization vector for AES encryption.
     * @return An encrypted device public key.
     * @throws InvalidKeyException In case provided public key is invalid.
     */
    public byte[] encryptDevicePublicKey(PublicKey devicePublicKey, PrivateKey clientEphemeralPrivateKey, PublicKey masterPublicKey, String activationOTP, String activationIdShort, byte[] activationNonce) throws InvalidKeyException {
        try {
            KeyGenerator keyGenerator = new KeyGenerator();
            byte[] activationIdShortBytes = activationIdShort.getBytes("UTF-8");
            SecretKey otpBasedSymmetricKey = keyGenerator.deriveSecretKeyFromPassword(activationOTP, activationIdShortBytes);
            byte[] devicePubKeyBytes = PowerAuthConfiguration.INSTANCE.getKeyConvertor().convertPublicKeyToBytes(devicePublicKey);
            SecretKey ephemeralKey = keyGenerator.computeSharedKey(clientEphemeralPrivateKey, masterPublicKey);
            AESEncryptionUtils aes = new AESEncryptionUtils();
            byte[] tmpData = aes.encrypt(devicePubKeyBytes, activationNonce, otpBasedSymmetricKey);
            return aes.encrypt(tmpData, activationNonce, ephemeralKey);
        } catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException ex) {
            Logger.getLogger(PowerAuthClientActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
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
     * @throws UnsupportedEncodingException In case system does not support UTF-8 encoding.
     */
    public boolean verifyServerDataSignature(String activationId, byte[] C_serverPublicKey, byte[] signature, PublicKey masterPublicKey) throws InvalidKeyException, UnsupportedEncodingException {
        try {
            byte[] activationIdBytes = activationId.getBytes("UTF-8");
            String activationIdBytesBase64 = BaseEncoding.base64().encode(activationIdBytes);
            String C_serverPublicKeyBase64 = BaseEncoding.base64().encode(C_serverPublicKey);
            byte[] result = (activationIdBytesBase64 + "&" + C_serverPublicKeyBase64).getBytes("UTF-8");
            return signatureUtils.validateECDSASignature(result, signature, masterPublicKey);
        } catch (SignatureException ex) {
            Logger.getLogger(PowerAuthClientActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    /**
     * Decrypt server public key using activation OTP and device private key. As a technical component for public key encryption, an ephemeral public key is
     * used (in order to deduce ephemeral symmetric key using ECDH).
     *
     * @param C_serverPublicKey Encrypted server public key.
     * @param devicePrivateKey Device private key.
     * @param ephemeralPublicKey Ephemeral public key.
     * @param activationOTP Activation OTP value.
     * @param activationIdShort Short activation OTP.
     * @param activationNonce Activation nonce, used as an initialization vector for AES encryption.
     * @return Decrypted server public key.
     * @throws InvalidKeyException In case some of the provided keys is invalid.
     */
    public PublicKey decryptServerPublicKey(byte[] C_serverPublicKey, PrivateKey devicePrivateKey, PublicKey ephemeralPublicKey, String activationOTP, String activationIdShort, byte[] activationNonce) throws InvalidKeyException {

        try {
            KeyGenerator keyGenerator = new KeyGenerator();
            SecretKey ephemeralSymmetricKey = keyGenerator.computeSharedKey(devicePrivateKey, ephemeralPublicKey);

            byte[] activationIdShortBytes = activationIdShort.getBytes("UTF-8");
            SecretKey otpBasedSymmetricKey = keyGenerator.deriveSecretKeyFromPassword(activationOTP, activationIdShortBytes);

            AESEncryptionUtils aes = new AESEncryptionUtils();
            byte[] decryptedTMP = aes.decrypt(C_serverPublicKey, activationNonce, ephemeralSymmetricKey);
            byte[] decryptedServerPublicKeyBytes = aes.decrypt(decryptedTMP, activationNonce, otpBasedSymmetricKey);

            return PowerAuthConfiguration.INSTANCE.getKeyConvertor().convertBytesToPublicKey(decryptedServerPublicKeyBytes);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException | UnsupportedEncodingException ex) {
            Logger.getLogger(PowerAuthClientActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Compute a fingerprint of the device public key. The fingerprint can be used for visual validation of an exchanged public key.
     *
     * @param devicePublicKey Public key for computing fingerprint.
     * @return Fingerprint of the public key.
     */
    public String computeDevicePublicKeyFingerprint(PublicKey devicePublicKey) {
        try {
            return ECPublicKeyFingerprint.compute(((ECPublicKey)devicePublicKey));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(PowerAuthServerActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Returns an activation status from the encrypted activation blob as described in PowerAuth 2.0 Specification.
     *
     * @param cStatusBlob Encrypted activation status blob
     * @param transportKey A key used to protect the transport.
     * @return Status information from the status blob
     * @throws InvalidKeyException When invalid key is provided.
     */
    public ActivationStatusBlobInfo getStatusFromEncryptedBlob(byte[] cStatusBlob, SecretKey transportKey) throws InvalidKeyException {
        try {

            if (cStatusBlob.length != 32) {
                // return mock status in case byte array has weird length
                ActivationStatusBlobInfo statusInfo = new ActivationStatusBlobInfo();
                statusInfo.setActivationStatus((byte) 5);
                statusInfo.setCounter(0L);
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
            statusInfo.setValid(prefix == 0xDEC0DED1);

            // fetch the activation status byte
            statusInfo.setActivationStatus(buffer.get(4));

            // fetch the counter info
            statusInfo.setCounter(buffer.getLong(5));

            // fetch the failed attempt count
            statusInfo.setFailedAttempts(buffer.get(13));

            // fetch the max allowed failed attempt count
            statusInfo.setMaxFailedAttempts(buffer.get(14));

            return statusInfo;
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            // Cryptography should be set correctly at this point
            Logger.getLogger(PowerAuthClientActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

}
