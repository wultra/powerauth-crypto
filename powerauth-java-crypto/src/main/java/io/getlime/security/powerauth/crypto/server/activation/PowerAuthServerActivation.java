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
package io.getlime.security.powerauth.crypto.server.activation;

import io.getlime.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import io.getlime.security.powerauth.crypto.lib.model.ActivationVersion;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Class implementing cryptography used on a server side in order to assure
 * PowerAuth Server activation related processes.
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthServerActivation {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthServerActivation.class);

    private final IdentifierGenerator identifierGenerator = new IdentifierGenerator();
    private final SignatureUtils signatureUtils = new SignatureUtils();
    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final KeyConvertor keyConvertor = new KeyConvertor();

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
     * Generate a pseudo-unique activation code. The format of activation code is "ABCDE-FGHIJ-KLMNO-PQRST".
     *
     * @return A new activation code.
     * @throws CryptoProviderException In case key cryptography provider is incorrectly initialized.
     */
    public String generateActivationCode() throws CryptoProviderException {
        return identifierGenerator.generateActivationCode();
    }

    /**
     * Generate a server related activation key pair.
     *
     * @return A new server key pair.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public KeyPair generateServerKeyPair() throws CryptoProviderException {
        return keyGenerator.generateKeyPair();
    }

    /**
     * Generate signature for the activation code.
     * <p>
     * Signature is then computed using the master private key.
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
        return signatureUtils.computeECDSASignature(bytes, masterPrivateKey);
    }

    /**
     * Generate a new server activation nonce.
     *
     * @return A new server activation nonce.
     * @throws CryptoProviderException In case key cryptography provider is incorrectly initialized.
     */
    public byte[] generateActivationNonce() throws CryptoProviderException {
        return keyGenerator.generateRandomBytes(16);
    }

    /**
     * Method validates the signature of the activation data in order to prove that a correct
     * client application is attempting to complete the activation.
     *
     * <p><b>PowerAuth protocol versions:</b>
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
     * @param signature Signature to be checked against.
     * @return True if the signature is correct, false otherwise.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean validateApplicationSignature(String activationIdShort, byte[] activationNonce, byte[] encryptedDevicePublicKey, byte[] applicationKey, byte[] applicationSecret, byte[] signature) throws GenericCryptoException, CryptoProviderException {
        String signatureBaseString = activationIdShort + "&"
                + Base64.getEncoder().encodeToString(activationNonce) + "&"
                + Base64.getEncoder().encodeToString(encryptedDevicePublicKey) + "&"
                + Base64.getEncoder().encodeToString(applicationKey);
        byte[] signatureExpected = new HMACHashUtilities().hash(applicationSecret, signatureBaseString.getBytes(StandardCharsets.UTF_8));
        return Arrays.equals(signatureExpected, signature);
    }

    /**
     * Decrypt the device public key using activation OTP.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * @param C_devicePublicKey Encrypted device public key.
     * @param activationIdShort Short activation ID.
     * @param masterPrivateKey Server master private key.
     * @param ephemeralPublicKey Ephemeral public key. 
     * @param activationOTP Activation OTP value.
     * @param activationNonce Activation nonce, used as an initialization vector
     * for AES encryption.
     * @return A decrypted public key.
     * @throws GenericCryptoException In case decryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public PublicKey decryptDevicePublicKey(byte[] C_devicePublicKey, String activationIdShort, PrivateKey masterPrivateKey, PublicKey ephemeralPublicKey, String activationOTP, byte[] activationNonce) throws GenericCryptoException, CryptoProviderException {
        try {
            // Derive longer key from short activation ID and activation OTP
            byte[] activationIdShortBytes = activationIdShort.getBytes(StandardCharsets.UTF_8);
            SecretKey otpBasedSymmetricKey = keyGenerator.deriveSecretKeyFromPassword(activationOTP, activationIdShortBytes);

            if (ephemeralPublicKey != null) { // is an extra ephemeral key encryption included?

                // Compute ephemeral secret key
                SecretKey ephemeralSymmetricKey = keyGenerator.computeSharedKey(masterPrivateKey, ephemeralPublicKey);

                // Decrypt device public key
                AESEncryptionUtils aes = new AESEncryptionUtils();
                byte[] decryptedTMP = aes.decrypt(C_devicePublicKey, activationNonce, ephemeralSymmetricKey);
                byte[] decryptedPublicKeyBytes = aes.decrypt(decryptedTMP, activationNonce, otpBasedSymmetricKey);
                return keyConvertor.convertBytesToPublicKey(decryptedPublicKeyBytes);

            } else { // extra encryption is not present, only OTP based key is used

                // Decrypt device public key
                AESEncryptionUtils aes = new AESEncryptionUtils();
                byte[] decryptedPublicKeyBytes = aes.decrypt(C_devicePublicKey, activationNonce, otpBasedSymmetricKey);
                return keyConvertor.convertBytesToPublicKey(decryptedPublicKeyBytes);

            }

        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Encrypt the server public key using activation OTP and device public key.
     * As a technical component for public key encryption, an ephemeral private
     * key is used (in order to deduce ephemeral symmetric key using ECDH).
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
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
     * @throws GenericCryptoException In case encryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] encryptServerPublicKey(PublicKey serverPublicKey, PublicKey devicePublicKey,
                                         PrivateKey ephemeralPrivateKey, String activationOTP, String activationIdShort, byte[] activationNonce)
            throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        // Convert public key to bytes
        byte[] serverPublicKeyBytes = keyConvertor.convertPublicKeyToBytes(serverPublicKey);

        // Generate symmetric keys
        SecretKey ephemeralSymmetricKey = keyGenerator.computeSharedKey(ephemeralPrivateKey, devicePublicKey);

        byte[] activationIdShortBytes = activationIdShort.getBytes(StandardCharsets.UTF_8);
        SecretKey otpBasedSymmetricKey = keyGenerator.deriveSecretKeyFromPassword(activationOTP,
                activationIdShortBytes);

        // Encrypt the data
        AESEncryptionUtils aes = new AESEncryptionUtils();
        byte[] encryptedTmp = aes.encrypt(serverPublicKeyBytes, activationNonce, otpBasedSymmetricKey);
        return aes.encrypt(encryptedTmp, activationNonce, ephemeralSymmetricKey);
    }

    /**
     * Returns an encrypted status blob as described in PowerAuth Specification.
     *
     * @param statusBlobInfo {@link ActivationStatusBlobInfo} object with activation status data to be encrypted.
     * @param challenge Challenge for activation status blob encryption. If non-null, then also {@code nonce} parameter must be provided.
     * @param nonce Nonce for activation status blob encryption. If non-null, then also {@code challenge} parameter must be provided.
     * @param transportKey A key used to protect the transport.
     * @return Encrypted status blob
     * @throws InvalidKeyException When invalid key is provided.
     * @throws GenericCryptoException In case encryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] encryptedStatusBlob(ActivationStatusBlobInfo statusBlobInfo, byte[] challenge, byte[] nonce, SecretKey transportKey)
            throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        // Validate inputs
        if (statusBlobInfo == null) {
            throw new GenericCryptoException("Required statusBlobInfo parameter is missing");
        }
        if (transportKey == null) {
            throw new GenericCryptoException("Required transportKey parameter is missing");
        }
        // Prepare variables that has different meaning, depended on the protocol version.
        final byte[] reserved;
        final byte[] ctrDataHash;
        final byte ctrByte;
        final byte ctrLookAhead;
        if (challenge != null) {
            // Protocol V3.1+, use values provided in the status blob info object.
            if (statusBlobInfo.getCtrDataHash() == null) {
                throw new GenericCryptoException("Missing ctrDataHash in statusBlobInfo object");
            }
            reserved = keyGenerator.generateRandomBytes(5);
            ctrDataHash = statusBlobInfo.getCtrDataHash();
            ctrByte = statusBlobInfo.getCtrByte();
            ctrLookAhead = statusBlobInfo.getCtrLookAhead();
        } else {
            // Legacy protocol versions (2.x, 3.0)
            //
            // In this case, ctrDataHash, ctrInfo, ctrLookAhead should be completely random values, because
            // mobile clients don't use them. The older protocols also use zero-IV for the encryption, so the first
            // block encrypted by AES should have as much entropy as possible.
            //
            final byte[] randomBytes = keyGenerator.generateRandomBytes(5 + 2 + 16);
            reserved = Arrays.copyOf(randomBytes, 5);
            ctrDataHash = Arrays.copyOfRange(randomBytes, 5 + 2, 5 + 2 + 16);
            ctrByte = randomBytes[5];
            ctrLookAhead = randomBytes[6];
        }
        // Prepare status blob data.
        final byte[] statusBlob = ByteBuffer.allocate(32)
                .putInt(ActivationStatusBlobInfo.ACTIVATION_STATUS_MAGIC_VALUE)     // 4 bytes
                .put(statusBlobInfo.getActivationStatus())   // 1 byte
                .put(statusBlobInfo.getCurrentVersion())     // 1 byte
                .put(statusBlobInfo.getUpgradeVersion())     // 1 byte
                .put(reserved)                               // 5 bytes
                .put(ctrByte)                                // 1 byte
                .put(statusBlobInfo.getFailedAttempts())     // 1 byte
                .put(statusBlobInfo.getMaxFailedAttempts())  // 1 byte
                .put(ctrLookAhead)                           // 1 byte
                .put(ctrDataHash)                            // 16 bytes
                .array();
        // Derive IV and encrypt status blob data.
        final byte[] iv = new KeyDerivationUtils().deriveIvForStatusBlobEncryption(challenge, nonce, transportKey);
        return new AESEncryptionUtils().encrypt(statusBlob, iv, transportKey, "AES/CBC/NoPadding");
    }

    /**
     * Calculate hash from value representing the hash based counter. HMAC-SHA256 is currently used as a hashing
     * function.
     *
     * @param ctrData Hash-based counter.
     * @param transportKey Transport key.
     * @return Hash calculated from provided hash-based counter.
     * @throws GenericCryptoException In case that key derivation fails or you provided invalid ctrData.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws InvalidKeyException In case that transport key is not valid.
     */
    public byte[] calculateHashFromHashBasedCounter(byte[] ctrData, SecretKey transportKey)
            throws CryptoProviderException, InvalidKeyException, GenericCryptoException {
        return new HashBasedCounterUtils().calculateHashFromHashBasedCounter(ctrData, transportKey);
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
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] computeServerDataSignature(String activationId, byte[] C_serverPublicKey, PrivateKey masterPrivateKey)
            throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        byte[] activationIdBytes = activationId.getBytes(StandardCharsets.UTF_8);
        String activationIdBytesBase64 = Base64.getEncoder().encodeToString(activationIdBytes);
        String C_serverPublicKeyBase64 = Base64.getEncoder().encodeToString(C_serverPublicKey);
        byte[] result = (activationIdBytesBase64 + "&" + C_serverPublicKeyBase64).getBytes(StandardCharsets.UTF_8);
        return signatureUtils.computeECDSASignature(result, masterPrivateKey);
    }

    /**
     * Compute a fingerprint for the version 2 activation. The fingerprint can be used for visual validation of exchanged device public key.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * @param devicePublicKey Public key for computing fingerprint.
     * @return Fingerprint of the public key.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws GenericCryptoException In case fingerprint could not be calculated.
     */
    public String computeActivationFingerprint(PublicKey devicePublicKey) throws GenericCryptoException, CryptoProviderException {
        return computeActivationFingerprint(devicePublicKey, null, null, ActivationVersion.VERSION_2);
    }

    /**
     * Compute a fingerprint for the version 3 activation. The fingerprint can be used for visual validation of exchanged device public key.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>3.0</li>
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

}
