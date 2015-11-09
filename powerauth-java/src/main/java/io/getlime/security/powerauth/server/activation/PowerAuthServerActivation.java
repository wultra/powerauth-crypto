package io.getlime.security.powerauth.server.activation;

import io.getlime.security.powerauth.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.lib.util.KeyConversionUtils;
import io.getlime.security.powerauth.lib.util.SignatureUtils;
import io.getlime.security.powerauth.lib.config.PowerAuthConstants;
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
    public byte[] generateActivationSignature(
            String activationIdShort,
            String activationOTP,
            PrivateKey masterPrivateKey) throws InvalidKeyException {
        try {
            byte[] bytes = (activationIdShort + "-" + activationOTP).getBytes("UTF-8");
            byte[] signature = signatureUtils.computeECDSASignature(bytes, masterPrivateKey);
            return signature;
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
     * Decrypt the device public key using activation OTP.
     *
     * @param C_devicePublicKey Encrypted device public key.
     * @param activationIdShort Short activation ID.
     * @param activationOTP Activation OTP value.
     * @param activationNonce Activation nonce, used as an initialization vector
     * for AES encryption.
     * @return A decrypted public key.
     */
    public PublicKey decryptDevicePublicKey(
            byte[] C_devicePublicKey,
            String activationIdShort,
            String activationOTP,
            byte[] activationNonce) {
        try {
            // Derive longer key from short activation ID and activation OTP
            byte[] activationIdShortBytes = activationIdShort.getBytes("UTF-8");
            SecretKey otpBasedSymmetricKey = new KeyGenerator().deriveSecretKeyFromPassword(activationOTP, activationIdShortBytes);

            // Decrypt device public key
            AESEncryptionUtils aes = new AESEncryptionUtils();
            byte[] decryptedPublicKeyBytes = aes.decrypt(C_devicePublicKey, activationNonce, otpBasedSymmetricKey);
            PublicKey devicePublicKey = new KeyConversionUtils().convertBytesToPublicKey(decryptedPublicKeyBytes);
            return devicePublicKey;
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
    public byte[] encryptServerPublicKey(
            PublicKey serverPublicKey,
            PublicKey devicePublicKey,
            PrivateKey ephemeralPrivateKey,
            String activationOTP,
            String activationIdShort,
            byte[] activationNonce) throws InvalidKeyException {
        try {

            // Convert public key to bytes
            byte[] serverPublicKeyBytes = new KeyConversionUtils().convertPublicKeyToBytes(serverPublicKey);

            // Generate symmetric keys
            KeyGenerator keyGenerator = new KeyGenerator();
            SecretKey ephemeralSymmetricKey = keyGenerator.computeSharedKey(ephemeralPrivateKey, devicePublicKey);

            byte[] activationIdShortBytes = activationIdShort.getBytes("UTF-8");
            SecretKey otpBasedSymmetricKey = keyGenerator.deriveSecretKeyFromPassword(activationOTP, activationIdShortBytes);

            // Encrypt the data
            AESEncryptionUtils aes = new AESEncryptionUtils();
            byte[] encryptedTMP = aes.encrypt(serverPublicKeyBytes, activationNonce, otpBasedSymmetricKey);
            byte[] encryptServerPublicKey = aes.encrypt(encryptedTMP, activationNonce, ephemeralSymmetricKey);
            return encryptServerPublicKey;

        } catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException ex) {
            Logger.getLogger(PowerAuthServerActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Compute an encrypted server public key signature using the Master Private
     * Key.
     *
     * @param C_serverPublicKey Encrypted server public key.
     * @param masterPrivateKey Master Private Key.
     * @return Signature of the encrypted server public key.
     * @throws InvalidKeyException If master private key is invalid.
     */
    public byte[] computeServerPublicKeySignature(
            byte[] C_serverPublicKey,
            PrivateKey masterPrivateKey) throws InvalidKeyException {
        try {
            return signatureUtils.computeECDSASignature(C_serverPublicKey, masterPrivateKey);
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

}
