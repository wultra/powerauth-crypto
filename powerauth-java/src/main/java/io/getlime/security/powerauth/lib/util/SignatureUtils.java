/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.lib.util;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;

import com.google.common.base.Joiner;

import io.getlime.security.powerauth.lib.config.PowerAuthConstants;

public class SignatureUtils {

    /**
     * Compute ECDSA signature of given bytes with a private key.
     *
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
     *
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
     * keys and counter.
     *
     * @param data Data to be signed.
     * @param signatureKeys Keys for computing the signature.
     * @param counter Counter / derived key index.
     * @return PowerAuth 2.0 signature for given data.
     * @throws InvalidKeyException
     */
    public String computePowerAuthSignature(byte[] data, List<SecretKey> signatureKeys, long counter) {
    	// Prepare a hash
    	HMACHashUtilities hmac = new HMACHashUtilities();
    	
    	// Prepare a counter
        byte[] ctr = ByteBuffer.allocate(16).putLong(counter).array();

        // Prepare holder for signature components
        String[] signatureComponents = new String[signatureKeys.size()];
            
        for (int i = 0; i < signatureKeys.size(); i++) {
           	byte[] signatureKey = new KeyConversionUtils().convertSharedSecretKeyToBytes(signatureKeys.get(i));
           	byte[] derivedKey = hmac.hash(signatureKey, ctr);
           	
           	for (int j = 0; j < i; j++) {
           		byte[] signatureKeyInner = new KeyConversionUtils().convertSharedSecretKeyToBytes(signatureKeys.get(j + 1));
            	byte[] derivedKeyInner = hmac.hash(signatureKeyInner, ctr);
                derivedKey = hmac.hash(derivedKey, derivedKeyInner);
            }
            	
            byte[] signatureLong = hmac.hash(data, derivedKey);
            	
            if (signatureLong.length < 4) { // assert
                throw new IndexOutOfBoundsException();
            }
            int index = signatureLong.length - 4;
            int number = (ByteBuffer.wrap(signatureLong).getInt(index) & 0x7FFFFFFF) % (int) (Math.pow(10, PowerAuthConstants.SIGNATURE_LENGTH));
            String signature = String.format("%0" + PowerAuthConstants.SIGNATURE_LENGTH + "d", number);
        	signatureComponents[i] = signature;
        }
        
        return Joiner.on("-").join(signatureComponents);
    }

    /**
     * Validate the PowerAuth 2.0 signature for given data using provided keys.
     *
     * @param data Data that were signed.
     * @param signature Data signature.
     * @param signatureKeys Keys for signature validation.
     * @param counter Counter.
     * @return Return "true" if signature matches, "false" otherwise.
     * @throws InvalidKeyException
     */
    public boolean validatePowerAuthSignature(byte[] data, String signature, List<SecretKey> signatureKeys, long counter) throws InvalidKeyException {
        return signature.equals(computePowerAuthSignature(data, signatureKeys, counter));
    }

}
