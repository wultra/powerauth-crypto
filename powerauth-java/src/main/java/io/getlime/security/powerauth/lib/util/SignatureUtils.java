package io.getlime.security.powerauth.lib.util;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import io.getlime.security.powerauth.lib.config.PowerAuthConstants;

public class SignatureUtils {

    /**
     * Compute ECDSA signature of given bytes with a private key.
     * @param bytes Bytes to be signed.
     * @param masterPrivateKey Private key for computing the signature.
     * @return Signature for given data.
     * @throws InvalidKeyException
     * @throws SignatureException 
     */
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

    /**
     * Validate an ECDSA signature against given data using a public key.
     * @param signedBytes Bytes that are signed.
     * @param signature Signature of the bytes.
     * @param masterPublicKey Public key for validating the signature.
     * @return Returns "true" if signature matches, "false" otherwise.
     * @throws InvalidKeyException
     * @throws SignatureException 
     */
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
    
    /**
     * Compute PowerAuth 2.0 signature for given data using a secret signature
     * key and counter.
     * @param data Data to be signed.
     * @param signatureKey Key for computing the signature.
     * @param counter Counter / derived key index.
     * @return PowerAuth 2.0 signature for given data.
     * @throws InvalidKeyException 
     */
    public String computePowerAuthSignature(byte[] data, SecretKey signatureKey, long counter) throws InvalidKeyException {
        try {
            byte[] ctr = ByteBuffer.allocate(16).putLong(counter).array();
            Mac hmacSha256 = Mac.getInstance("HmacSHA256", "BC");
            byte[] keyBytes = new KeyConversionUtils().convertSharedSecretKeyToBytes(signatureKey);
            SecretKey hmacKey = new SecretKeySpec(keyBytes, "HmacSHA256");
            hmacSha256.init(hmacKey);
            byte[] signatureLong = hmacSha256.doFinal(ctr);
            if (signatureLong.length < 4) { // assert
                throw new IndexOutOfBoundsException();
            }
            int index = signatureLong.length - 4;
            int number = (ByteBuffer.wrap(signatureLong).getInt(index) & 0x7FFFFFFF) % (int)(Math.pow(10, PowerAuthConstants.SIGNATURE_LENGTH));
            String signature = String.format("%0" + PowerAuthConstants.SIGNATURE_LENGTH + "d", number);
            return signature;
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(SignatureUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    /**
     * Validate the PowerAuth 2.0 signature for given data.
     * @param data Data that were signed.
     * @param signature Data signature.
     * @param signatureKey Key for signature validation.
     * @param counter Counter.
     * @return Return "true" if signature matches, "false" otherwise.
     * @throws InvalidKeyException 
     */
    public boolean validatePowerAuthSignature(byte[] data, String signature, SecretKey signatureKey, long counter) throws InvalidKeyException {
        return signature.equals(computePowerAuthSignature(data, signatureKey, counter));
    }

}
