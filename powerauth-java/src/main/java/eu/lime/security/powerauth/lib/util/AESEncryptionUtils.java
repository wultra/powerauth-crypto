package eu.lime.security.powerauth.lib.util;

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
