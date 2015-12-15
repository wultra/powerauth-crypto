/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.client.activation;

import io.getlime.security.powerauth.lib.config.PowerAuthConstants;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.lib.util.KeyConversionUtils;
import io.getlime.security.powerauth.lib.util.SignatureUtils;
import io.getlime.security.powerauth.server.activation.PowerAuthServerActivation;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

public class PowerAuthClientActivation {

    private final SignatureUtils signatureUtils = new SignatureUtils();

    /**
     * Verify the signature of activation data using Master Public Key.
     * Signature is computed as the concatenation of activationIdShort and
     * activationOTP, separated with the "-" character:
     *
     * activationData = activationIdShort + "-" + activationOTP
     *
     * @param activationIdShort Short activation ID.
     * @param activationOTP Activation OTP value.
     * @param signature Activation data signature.
     * @param masterPublicKey Master Public Key.
     * @return Returns "true" if the signature matches activation data, "false"
     * otherwise.
     * @throws InvalidKeyException If provided master public key is invalid.
     */
    public boolean verifyActivationDataSignature(
            String activationIdShort,
            String activationOTP,
            byte[] signature,
            PublicKey masterPublicKey) throws InvalidKeyException {
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
     * Encrypt a device public key using the activation OTP.
     *
     * @param devicePublicKey Device public key to be encrypted.
     * @param activationOTP Activation OTP value.
     * @param activationIdShort Short activation ID.
     * @param activationNonce Activation nonce, used as an initialization vector
     * for AES encryption.
     * @return An encrypted device public key.
     * @throws InvalidKeyException In case provided public key is invalid.
     */
    public byte[] encryptDevicePublicKey(
            PublicKey devicePublicKey,
            String activationOTP,
            String activationIdShort,
            byte[] activationNonce) throws InvalidKeyException {
        try {
            KeyGenerator keyGenerator = new KeyGenerator();
            byte[] activationIdShortBytes = activationIdShort.getBytes("UTF-8");
            SecretKey otpBasedSymmetricKey = keyGenerator.deriveSecretKeyFromPassword(activationOTP, activationIdShortBytes);
            byte[] devicePubKeyBytes = new KeyConversionUtils().convertPublicKeyToBytes(devicePublicKey);
            AESEncryptionUtils aes = new AESEncryptionUtils();
            return aes.encrypt(devicePubKeyBytes, activationNonce, otpBasedSymmetricKey);
        } catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException ex) {
            Logger.getLogger(PowerAuthClientActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Verify signature of the encrypted server public key using Master Public
     * Key.
     *
     * @param C_serverPublicKey Encrypted server public key.
     * @param signature Encrypted server public key signature.
     * @param masterPublicKey Master Public Key.
     * @return Returns "true" if signature matches encrypted data, "false"
     * otherwise.
     * @throws InvalidKeyException If provided master public key is invalid.
     */
    public boolean verifyServerPublicKeySignature(
            byte[] C_serverPublicKey,
            byte[] signature,
            PublicKey masterPublicKey) throws InvalidKeyException {
        try {
            return signatureUtils.validateECDSASignature(C_serverPublicKey, signature, masterPublicKey);
        } catch (SignatureException ex) {
            Logger.getLogger(PowerAuthClientActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    /**
     * Decrypt server public key using activation OTP and device private key. As
     * a technical component for public key encryption, an ephemeral public key
     * is used (in order to deduce ephemeral symmetric key using ECDH).
     *
     * @param C_serverPublicKey Encrypted server public key.
     * @param devicePrivateKey Device private key.
     * @param ephemeralPublicKey Ephemeral public key.
     * @param activationOTP Activation OTP value.
     * @param activationIdShort Short activation OTP.
     * @param activationNonce Activation nonce, used as an initialization vector
     * for AES encryption.
     * @return Decrypted server public key.
     * @throws InvalidKeyException In case some of the provided keys is invalid.
     */
    public PublicKey decryptServerPublicKey(
            byte[] C_serverPublicKey,
            PrivateKey devicePrivateKey,
            PublicKey ephemeralPublicKey,
            String activationOTP,
            String activationIdShort,
            byte[] activationNonce) throws InvalidKeyException {

        try {
            KeyGenerator keyGenerator = new KeyGenerator();
            SecretKey ephemeralSymmetricKey = keyGenerator.computeSharedKey(devicePrivateKey, ephemeralPublicKey);

            byte[] activationIdShortBytes = activationIdShort.getBytes("UTF-8");
            SecretKey otpBasedSymmetricKey = keyGenerator.deriveSecretKeyFromPassword(activationOTP, activationIdShortBytes);

            AESEncryptionUtils aes = new AESEncryptionUtils();
            byte[] serverPublicKeyBytes = aes.decrypt(
                    aes.decrypt(
                            C_serverPublicKey,
                            activationNonce,
                            ephemeralSymmetricKey),
                    activationNonce,
                    otpBasedSymmetricKey);
            return new KeyConversionUtils().convertBytesToPublicKey(serverPublicKeyBytes);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException | UnsupportedEncodingException ex) {
            Logger.getLogger(PowerAuthClientActivation.class.getName()).log(Level.SEVERE, null, ex);
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
    public int computeDevicePublicKeyFingerprint(PublicKey devicePublicKey) {
        try {
            byte[] devicePublicKeyBytes = new KeyConversionUtils().convertPublicKeyToBytes(devicePublicKey);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(devicePublicKeyBytes);
            if (hash.length < 4) { // assert
                throw new IndexOutOfBoundsException();
            }
            int index = hash.length - 4;
            int number = (ByteBuffer.wrap(hash).getInt(index) & 0x7FFFFFFF) % (int) (Math.pow(10, PowerAuthConstants.FINGERPRINT_LENGTH));
            return number;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(PowerAuthServerActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return 0;
    }
    
    /**
     * Returns an activation status from the encrypted activation blob as described in PowerAuth 2.0 Specification.
     * @param cStatusBlob Encrypted activation status blob
     * @param transportKey A key used to protect the transport.
     * @return Status information from the status blob
     * @throws InvalidKeyException
     */
    public ActivationStatusBlobInfo getStatusFromEncryptedBlob(byte[] cStatusBlob, SecretKey transportKey)
            throws InvalidKeyException {
        try {
        	
        	// Decrypt the status blob
        	AESEncryptionUtils aes = new AESEncryptionUtils();
        	byte[] zeroIv = new byte[16];
            byte[] statusBlob = aes.decrypt(cStatusBlob, zeroIv, transportKey);
        	
            // Prepare objects to read status info into
        	ActivationStatusBlobInfo statusInfo = new ActivationStatusBlobInfo();
        	ByteBuffer buffer = ByteBuffer.wrap(statusBlob);
        	
        	// check if the prefix is OK
        	int prefix = buffer.getInt(0);
        	statusInfo.setValid(prefix == 0xDEADBEEF);
        	
        	// fetch the activation status byte
        	statusInfo.setActivationStatus(buffer.get(4));
        	
        	// fetch the counter info
        	statusInfo.setCounter(buffer.getInt(5));
        	
        	return statusInfo;
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            // Cryptography should be set correctly at this point
            Logger.getLogger(PowerAuthClientActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

}
