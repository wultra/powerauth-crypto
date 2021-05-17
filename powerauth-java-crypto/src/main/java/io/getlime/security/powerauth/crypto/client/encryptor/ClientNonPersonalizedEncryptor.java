package io.getlime.security.powerauth.crypto.client.encryptor;

import io.getlime.security.powerauth.crypto.lib.encryptor.NonPersonalizedEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.NonPersonalizedEncryptedMessage;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * Class that simulates client side encryption steps.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * Warning: this class will be removed in the future, use ECIES encryption for PowerAuth protocol version 3.0 or higher.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class ClientNonPersonalizedEncryptor {

    private final NonPersonalizedEncryptor encryptor;

    private final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Create a new client side non-personalized encryptor using provided app key (for reference in encrypted object)
     * and master public key.
     *
     * @param appKey App key.
     * @param masterPublicKey Master Server Public Key.
     * @throws InvalidKeyException In case an invalid key is provided.
     * @throws GenericCryptoException In case of any other cryptography error.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    @SuppressWarnings("deprecation")
    public ClientNonPersonalizedEncryptor(byte[] appKey, PublicKey masterPublicKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {

        final KeyGenerator generator = new KeyGenerator();
        byte[] sessionIndex = generator.generateRandomBytes(16);
        KeyPair ephemeralKeyPair = generator.generateKeyPair();
        final SecretKey ephemeralSecretKey = generator.computeSharedKey(ephemeralKeyPair.getPrivate(), masterPublicKey);
        final SecretKey sessionRelatedSecretKey = generator.deriveSecretKeyHmacLegacy(ephemeralSecretKey, sessionIndex);

        final byte[] sessionRelatedSecretKeyBytes = keyConvertor.convertSharedSecretKeyToBytes(sessionRelatedSecretKey);
        final byte[] ephemeralPublicKeyBytes = keyConvertor.convertPublicKeyToBytes(ephemeralKeyPair.getPublic());

        this.encryptor = new NonPersonalizedEncryptor(appKey, sessionRelatedSecretKeyBytes, sessionIndex, ephemeralPublicKeyBytes);
    }

    /**
     * Encrypt data using current encryptor (non-personalized encryption).
     * @param data Original data.
     * @return Encrypted payload.
     * @throws InvalidKeyException In case encryption key is invalid.
     * @throws GenericCryptoException In case encryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public NonPersonalizedEncryptedMessage encrypt(byte[] data) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return this.encryptor.encrypt(data);
    }

    /**
     * Decrypt original data from encrypted using current encryptor (non-personalized encryption).
     * @param message Encrypted payload message.
     * @return Original data.
     * @throws InvalidKeyException In case decryption key is invalid.
     * @throws GenericCryptoException In case decryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] decrypt(NonPersonalizedEncryptedMessage message) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return this.encryptor.decrypt(message);
    }

}
