package eu.lime.security.powerauth.lib.util;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SignatureUtils {

    public byte[] computeECDSASignature(byte[] bytes, PrivateKey masterPrivateKey) throws InvalidKeyException, SignatureException {
        try {
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initSign(masterPrivateKey);
            ecdsa.update(bytes);
            byte[] signature = ecdsa.sign();
            return signature;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SignatureUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public boolean validateECDSASignature(byte[] signedBytes, byte[] signature, PublicKey masterPublicKey) throws InvalidKeyException, SignatureException {
        try {
            Signature ecdsa = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsa.initVerify(masterPublicKey);
            ecdsa.update(signedBytes);
            boolean isValid = ecdsa.verify(signature);
            return isValid;
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(SignatureUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
    
    public byte[] computePowerAuthSignature(byte[] data, SecretKey signatureKey, Long counter) throws InvalidKeyException {
        try {
            byte[] ctr = ByteBuffer.allocate(16).putLong(counter).array();
            Mac hmacSha256 = Mac.getInstance("HmacSHA256", "BC");
            byte[] keyBytes = new KeyConversionUtils().convertSharedSecretKeyToBytes(signatureKey);
            SecretKey hmacKey = new SecretKeySpec(keyBytes, "HmacSHA256");
            hmacSha256.init(hmacKey);
            byte[] signature = hmacSha256.doFinal(ctr);
            return signature;
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(SignatureUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public boolean validatePowerAuthSignature(byte[] data, byte[] signature, SecretKey signatureKey, Long counter) throws InvalidKeyException {
        return Arrays.equals(data, computePowerAuthSignature(data, signatureKey, counter));
    }

}
