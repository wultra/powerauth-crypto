package io.getlime.security.powerauth.lib.util;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

public class KeyConversionUtils {
    
    /**
     * Converts an EC public key to a byte array by encoding Q point parameter.
     * @param publicKey An EC public key to be converted.
     * @return A byte array representation of the EC public key.
     */
    public byte[] convertPublicKeyToBytes(PublicKey publicKey) {
        ECPublicKey ecpk = (ECPublicKey)publicKey;
        return ecpk.getQ().getEncoded();
    }
    
    /**
     * Converts byte array to an EC public key, by decoding the Q point
     * parameter.
     * @param keyBytes Bytes to be converted to EC public key.
     * @return An instance of the EC public key on success, or null on failure.
     * @throws InvalidKeySpecException When provided bytes are not a correct
     * key representation.
     */
    public PublicKey convertBytesToPublicKey(byte[] keyBytes) throws InvalidKeySpecException {
        try {
            KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
            
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            ECPoint point = ecSpec.getCurve().decodePoint(keyBytes);
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
            
            ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(pubSpec);
            return publicKey;
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(this.getClass().getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    /**
     * Converts an EC private key to bytes by encoding the D number parameter.
     * @param privateKey An EC private key to be converted to bytes.
     * @return A byte array containing the representation of the EC private key.
     */
    public byte[] convertPrivateKeyToBytes(PrivateKey privateKey) {
        ECPrivateKey ecpk = (ECPrivateKey)privateKey;
        return ecpk.getD().toByteArray();
    }

    /**
     * Convert a byte array to an EC private key by decoding the D number
     * parameter.
     * @param keyBytes Bytes to be converted to the EC private key.
     * @return An instance of EC private key decoded from the input bytes.
     * @throws InvalidKeySpecException The provided key bytes are not a valid 
     * EC private key.
     */
    public PrivateKey convertBytesToPrivateKey(byte[] keyBytes) throws InvalidKeySpecException {
        try {
            KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
            
            BigInteger keyInteger = new BigInteger(keyBytes);
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            ECPrivateKeySpec pubSpec = new ECPrivateKeySpec(keyInteger, ecSpec);
            
            ECPrivateKey privateKey = (ECPrivateKey) kf.generatePrivate(pubSpec);
            return privateKey;
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(this.getClass().getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }


    /**
     * Converts a shared secret key (usually used for AES based operations)
     * to a byte array.
     * @param sharedSecretKey A shared key to be converted to bytes.
     * @return A byte array representation of the shared secret key.
     */
    public byte[] convertSharedSecretKeyToBytes(SecretKey sharedSecretKey) {
        return sharedSecretKey.getEncoded();
    }

    /**
     * Converts a byte array to the secret shared key (usually used for AES
     * based operations).
     * @param bytesSecretKey Bytes representing the shared key.
     * @return An instance of the secret key by decoding from provided bytes.
     */
    public SecretKey convertBytesToSharedSecretKey(byte[] bytesSecretKey) {
        return new SecretKeySpec(bytesSecretKey, "AES/CBC/NoPadding");
    }
    
    
}
