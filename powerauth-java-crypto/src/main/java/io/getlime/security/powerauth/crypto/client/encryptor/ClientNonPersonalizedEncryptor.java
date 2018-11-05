package io.getlime.security.powerauth.crypto.client.encryptor;

import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.NonPersonalizedEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.NonPersonalizedEncryptedMessage;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * Class that simulates client side encryption steps.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class ClientNonPersonalizedEncryptor {

    private NonPersonalizedEncryptor encryptor;

    /**
     * Create a new client side non-personalized encryptor using provided app key (for reference in encrypted object)
     * and master public key.
     *
     * @param appKey App key.
     * @param masterPublicKey Master Server Public Key.
     * @throws InvalidKeyException In case an invalid key is provided.
     * @throws GenericCryptoException In case of any other cryptography error.
     */
    public ClientNonPersonalizedEncryptor(byte[] appKey, PublicKey masterPublicKey) throws InvalidKeyException, GenericCryptoException {

        final KeyGenerator generator = new KeyGenerator();
        byte[] sessionIndex = generator.generateRandomBytes(16);
        KeyPair ephemeralKeyPair = generator.generateKeyPair();
        if (ephemeralKeyPair == null) {
            throw new InvalidKeyException("Unable to generate EC key pair. Check your Bouncy Castle settings.");
        }
        final SecretKey ephemeralSecretKey = generator.computeSharedKey(ephemeralKeyPair.getPrivate(), masterPublicKey);
        final SecretKey sessionRelatedSecretKey = generator.deriveSecretKeyHmac(ephemeralSecretKey, sessionIndex);

        final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
        final byte[] sessionRelatedSecretKeyBytes = keyConversion.convertSharedSecretKeyToBytes(sessionRelatedSecretKey);
        final byte[] ephemeralPublicKeyBytes = keyConversion.convertPublicKeyToBytes(ephemeralKeyPair.getPublic());

        this.encryptor = new NonPersonalizedEncryptor(appKey, sessionRelatedSecretKeyBytes, sessionIndex, ephemeralPublicKeyBytes);
    }

    /**
     * Encrypt data using current encryptor (non-personalized encryption).
     * @param data Original data.
     * @return Encrypted payload.
     * @throws GenericCryptoException In case encryption fails.
     */
    public NonPersonalizedEncryptedMessage encrypt(byte[] data) throws GenericCryptoException {
        return this.encryptor.encrypt(data);
    }

    /**
     * Decrypt original data from encrypted using current encryptor (non-personalized encryption).
     * @param message Encrypted payload message.
     * @return Original data.
     * @throws GenericCryptoException In case decryption fails.
     */
    public byte[] decrypt(NonPersonalizedEncryptedMessage message) throws GenericCryptoException {
        return this.encryptor.decrypt(message);
    }

}
