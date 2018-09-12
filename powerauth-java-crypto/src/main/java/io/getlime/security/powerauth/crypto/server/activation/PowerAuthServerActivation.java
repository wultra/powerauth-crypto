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
package io.getlime.security.powerauth.crypto.server.activation;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.crypto.lib.util.ECPublicKeyFingerprint;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class implementing cryptography used on a server side in order to assure
 * PowerAuth Server activation related processes.
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthServerActivation {

    private final IdentifierGenerator identifierGenerator = new IdentifierGenerator();
    private final SignatureUtils signatureUtils = new SignatureUtils();

    /**
     * Generate a pseudo-unique activation ID. Technically, this is UUID level 4
     * identifier. PowerAuth Server implementation should validate uniqueness in
     * database, for the very unlikely case of collision.
     *
     * @return A new activation ID (UUID level 4).
     */
    public String generateActivationId() {
        return identifierGenerator.generateActivationId();
    }

    /**
     * Generate a pseudo-unique short activation ID. Technically, the result is
     * a string with 5+5 random Base32 characters (separated with the "-"
     * character). PowerAuth Server implementation should validate that this
     * identifier is unique among all activation records in CREATED or OTP_USED
     * states, so that there are no collisions in activations.
     *
     * @return A new short activation ID.
     */
    public String generateActivationIdShort() {
        return identifierGenerator.generateActivationIdShort();
    }

    /**
     * Generate a pseudo-unique activation OTP. Technically, the result is a
     * string with 5+5 random Base32 characters (separated with the "-"
     * character).
     *
     * @return A new activation OTP.
     */
    public String generateActivationOTP() {
        return identifierGenerator.generateActivationOTP();
    }

    /**
     * Generate a pseudo-unique activation code. The format of activation code is "ABCDE-FGHIJ-KLMNO-PQRST".
     *
     * @return A new activation code.
     */
    public String generateActivationCode() {
        return identifierGenerator.generateActivationCode();
    }

    /**
     * Generate a server related activation key pair.
     *
     * @return A new server key pair.
     */
    public KeyPair generateServerKeyPair() {
        return new KeyGenerator().generateKeyPair();
    }

    /**
     * Generate signature for the activation data. Activation data are
     * constructed as a concatenation of activationIdShort and activationOTP,
     * both values are separated with the "-" character:
     *
     * activationData = activationIdShort + "_" + activationOTP
     *
     * Signature is then computed using the master private key.
     *
     * @param activationIdShort Short activation ID.
     * @param activationOTP Activation OTP value.
     * @param masterPrivateKey Master Private Key.
     * @return Signature of activation data using Master Private Key.
     * @throws InvalidKeyException In case Master Private Key is invalid.
     */
    public byte[] generateActivationSignature(String activationIdShort, String activationOTP,
                                              PrivateKey masterPrivateKey) throws InvalidKeyException {
        try {
            byte[] bytes = (activationIdShort + "-" + activationOTP).getBytes("UTF-8");
            return signatureUtils.computeECDSASignature(bytes, masterPrivateKey);
        } catch (UnsupportedEncodingException | SignatureException ex) {
            Logger.getLogger(PowerAuthServerActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Generate signature for the activation code.
     *
     * Signature is then computed using the master private key.
     *
     * @param activationCode Short activation ID.
     * @param masterPrivateKey Master Private Key.
     * @return Signature of activation data using Master Private Key.
     * @throws InvalidKeyException In case Master Private Key is invalid.
     */
    public byte[] generateActivationSignature(String activationCode,
                                              PrivateKey masterPrivateKey) throws InvalidKeyException {
        try {
            byte[] bytes = activationCode.getBytes("UTF-8");
            return signatureUtils.computeECDSASignature(bytes, masterPrivateKey);
        } catch (UnsupportedEncodingException | SignatureException ex) {
            Logger.getLogger(PowerAuthServerActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Generate a new server activation nonce.
     *
     * @return A new server activation nonce.
     */
    public byte[] generateActivationNonce() {
        return new KeyGenerator().generateRandomBytes(16);
    }

    /**
     * Method validates the signature of the activation data in order to prove that a correct
     * client application is attempting to complete the activation.
     * @param activationIdShort Short activation ID.
     * @param activationNonce Client activation nonce.
     * @param encryptedDevicePublicKey Encrypted device public key.
     * @param applicationKey Application identifier.
     * @param applicationSecret Application secret.
     * @param signature Signature to be checked against.
     * @return True if the signature is correct, false otherwise.
     */
    public boolean validateApplicationSignature(String activationIdShort, byte[] activationNonce, byte[] encryptedDevicePublicKey, byte[] applicationKey, byte[] applicationSecret, byte[] signature) {
        try {
            String signatureBaseString = activationIdShort + "&"
                    + BaseEncoding.base64().encode(activationNonce) + "&"
                    + BaseEncoding.base64().encode(encryptedDevicePublicKey) + "&"
                    + BaseEncoding.base64().encode(applicationKey);
            byte[] signatureExpected = new HMACHashUtilities().hash(applicationSecret, signatureBaseString.getBytes("UTF-8"));
            return Arrays.equals(signatureExpected, signature);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(PowerAuthClientActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    /**
     * Decrypt the device public key using activation OTP.
     *
     * @param C_devicePublicKey Encrypted device public key.
     * @param activationIdShort Short activation ID.
     * @param masterPrivateKey Server master private key.
     * @param ephemeralPublicKey Ephemeral public key. 
     * @param activationOTP Activation OTP value.
     * @param activationNonce Activation nonce, used as an initialization vector
     * for AES encryption.
     * @return A decrypted public key.
     */
    public PublicKey decryptDevicePublicKey(byte[] C_devicePublicKey, String activationIdShort, PrivateKey masterPrivateKey, PublicKey ephemeralPublicKey, String activationOTP, byte[] activationNonce) {
        try {
            // Derive longer key from short activation ID and activation OTP
            byte[] activationIdShortBytes = activationIdShort.getBytes("UTF-8");
            SecretKey otpBasedSymmetricKey = new KeyGenerator().deriveSecretKeyFromPassword(activationOTP, activationIdShortBytes);

            if (ephemeralPublicKey != null) { // is an extra ephemeral key encryption included?

                // Compute ephemeral secret key
                KeyGenerator keyGenerator = new KeyGenerator();
                SecretKey ephemeralSymmetricKey = keyGenerator.computeSharedKey(masterPrivateKey, ephemeralPublicKey);

                // Decrypt device public key
                AESEncryptionUtils aes = new AESEncryptionUtils();
                byte[] decryptedTMP = aes.decrypt(C_devicePublicKey, activationNonce, ephemeralSymmetricKey);
                byte[] decryptedPublicKeyBytes = aes.decrypt(decryptedTMP, activationNonce, otpBasedSymmetricKey);
                return PowerAuthConfiguration.INSTANCE.getKeyConvertor().convertBytesToPublicKey(decryptedPublicKeyBytes);

            } else { // extra encryption is not present, only OTP based key is used

                // Decrypt device public key
                AESEncryptionUtils aes = new AESEncryptionUtils();
                byte[] decryptedPublicKeyBytes = aes.decrypt(C_devicePublicKey, activationNonce, otpBasedSymmetricKey);
                return PowerAuthConfiguration.INSTANCE.getKeyConvertor().convertBytesToPublicKey(decryptedPublicKeyBytes);

            }

        } catch (IllegalBlockSizeException | InvalidKeySpecException | BadPaddingException | InvalidKeyException | UnsupportedEncodingException ex) {
            Logger.getLogger(PowerAuthServerActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Encrypt the server public key using activation OTP and device public key.
     * As a technical component for public key encryption, an ephemeral private
     * key is used (in order to deduce ephemeral symmetric key using ECDH).
     *
     * @param serverPublicKey Server public key to be encrypted.
     * @param devicePublicKey Device public key used for encryption.
     * @param ephemeralPrivateKey Ephemeral private key.
     * @param activationOTP Activation OTP value.
     * @param activationIdShort Short activation ID.
     * @param activationNonce Activation nonce, used as an initialization vector
     * for AES encryption.
     * @return Encrypted server public key.
     * @throws InvalidKeyException In case some of the provided keys is invalid.
     */
    public byte[] encryptServerPublicKey(PublicKey serverPublicKey, PublicKey devicePublicKey,
                                         PrivateKey ephemeralPrivateKey, String activationOTP, String activationIdShort, byte[] activationNonce)
            throws InvalidKeyException {
        try {

            // Convert public key to bytes
            byte[] serverPublicKeyBytes = PowerAuthConfiguration.INSTANCE.getKeyConvertor().convertPublicKeyToBytes(serverPublicKey);

            // Generate symmetric keys
            KeyGenerator keyGenerator = new KeyGenerator();
            SecretKey ephemeralSymmetricKey = keyGenerator.computeSharedKey(ephemeralPrivateKey, devicePublicKey);

            byte[] activationIdShortBytes = activationIdShort.getBytes("UTF-8");
            SecretKey otpBasedSymmetricKey = keyGenerator.deriveSecretKeyFromPassword(activationOTP,
                    activationIdShortBytes);

            // Encrypt the data
            AESEncryptionUtils aes = new AESEncryptionUtils();
            byte[] encryptedTMP = aes.encrypt(serverPublicKeyBytes, activationNonce, otpBasedSymmetricKey);
            return aes.encrypt(encryptedTMP, activationNonce, ephemeralSymmetricKey);

        } catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException ex) {
            Logger.getLogger(PowerAuthServerActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Returns an encrypted status blob as described in PowerAuth 2.0 Specification.
     * @param statusByte Byte determining the status of the activation.
     * @param currentVersionByte Current crypto protocol version.
     * @param upgradeVersionByte Crypto version for possible migration.
     * @param failedAttempts Number of failed attempts at the moment.
     * @param maxFailedAttempts Number of allowed failed attempts.
     * @param transportKey A key used to protect the transport.
     * @return Encrypted status blob
     * @throws InvalidKeyException When invalid key is provided.
     */
    public byte[] encryptedStatusBlob(byte statusByte, byte currentVersionByte, byte upgradeVersionByte, byte failedAttempts, byte maxFailedAttempts, SecretKey transportKey)
            throws InvalidKeyException {
        try {
            byte[] padding = new KeyGenerator().generateRandomBytes(17);
            byte[] zeroIv = new byte[16];
            byte[] reservedBytes = new byte[6];
            byte[] statusBlob = ByteBuffer.allocate(32)
                    .putInt(ActivationStatusBlobInfo.ACTIVATION_STATUS_MAGIC_VALUE)     // 4 bytes
                    .put(statusByte)         // 1 byte
                    .put(currentVersionByte) // 1 byte
                    .put(upgradeVersionByte) // 1 byte
                    .put(reservedBytes)      // 6 bytes
                    .put(failedAttempts)     // 1 byte
                    .put(maxFailedAttempts)  // 1 byte
                    .put(padding)            // 17 bytes
                    .array();
            AESEncryptionUtils aes = new AESEncryptionUtils();
            return aes.encrypt(statusBlob, zeroIv, transportKey, "AES/CBC/NoPadding");
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            // Cryptography should be set correctly at this point
            Logger.getLogger(PowerAuthServerActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Compute an activation ID and encrypted server public key signature
     * using the Master Private Key.
     *
     * @param activationId Activation ID
     * @param C_serverPublicKey Encrypted server public key.
     * @param masterPrivateKey Master Private Key.
     * @return Signature of the encrypted server public key.
     * @throws InvalidKeyException If master private key is invalid.
     * @throws UnsupportedEncodingException In case UTF-8 is not supported on the system.
     */
    public byte[] computeServerDataSignature(String activationId, byte[] C_serverPublicKey, PrivateKey masterPrivateKey)
            throws InvalidKeyException, UnsupportedEncodingException {
        try {
            byte[] activationIdBytes = activationId.getBytes("UTF-8");
            String activationIdBytesBase64 = BaseEncoding.base64().encode(activationIdBytes);
            String C_serverPublicKeyBase64 = BaseEncoding.base64().encode(C_serverPublicKey);
            byte[] result = (activationIdBytesBase64 + "&" + C_serverPublicKeyBase64).getBytes("UTF-8");
            return signatureUtils.computeECDSASignature(result, masterPrivateKey);
        } catch (SignatureException ex) {
            Logger.getLogger(PowerAuthServerActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Compute a fingerprint of the device public key. The fingerprint can be
     * used for visual validation of an exchanged public key.
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

}
