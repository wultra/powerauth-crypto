package io.getlime.security.powerauth.lib.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AESEncryptionUtils {

    /**
     * Encrypt given data using AES/CBC/PKCS5Padding with given initialization
     * vector and secret key.
     *
     * @param bytes Bytes to be encrypted.
     * @param iv Initialization vector.
     * @param secret Secret signature key.
     * @return Encrypted bytes.
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public byte[] encrypt(byte[] bytes, byte[] iv, SecretKey secret) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        try {
            Cipher cipherForCryptoResponse = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            cipherForCryptoResponse.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(iv));
            byte[] cryptoResponseData = cipherForCryptoResponse.doFinal(bytes);
            return cryptoResponseData;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(AESEncryptionUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Decrypt given data using AES/CBC/PKCS5Padding with given initialization
     * vector and secret key.
     *
     * @param bytes Encrypted bytes to be decrypted.
     * @param iv Initialization vector.
     * @param secret Secret signature key.
     * @return Original decrypted bytes.
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public byte[] decrypt(byte[] bytes, byte[] iv, SecretKey secret) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        try {
            Cipher cipherForCryptoResponse = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            cipherForCryptoResponse.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
            byte[] cryptoResponseData = cipherForCryptoResponse.doFinal(bytes);
            return cryptoResponseData;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(AESEncryptionUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

}
