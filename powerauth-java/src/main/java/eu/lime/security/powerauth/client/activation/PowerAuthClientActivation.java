package eu.lime.security.powerauth.client.activation;

import com.google.common.io.BaseEncoding;
import eu.lime.security.powerauth.lib.config.PowerAuthConstants;
import eu.lime.security.powerauth.lib.generator.KeyGenerator;
import eu.lime.security.powerauth.lib.util.AESEncryptionUtils;
import eu.lime.security.powerauth.lib.util.KeyConversionUtils;
import eu.lime.security.powerauth.lib.util.SignatureUtils;
import eu.lime.security.powerauth.server.activation.PowerAuthServerActivation;
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
            int number = (ByteBuffer.wrap(hash).getInt(index) & 0x7FFFFFFF) % (int)(Math.pow(10, PowerAuthConstants.FINGERPRINT_LENGTH));
            return number;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(PowerAuthServerActivation.class.getName()).log(Level.SEVERE, null, ex);
        }
        return 0;
    }

}
