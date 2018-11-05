/*
 * PowerAuth Crypto Library
 * Copyright 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.crypto.lib.util;

import com.google.common.base.Joiner;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.List;

/**
 * Utility class for signature calculation and validation used both on client and server.
 *
 * @author Petr Dvorak
 *
 */
public class SignatureUtils {

    /**
     * Compute ECDSA signature of given bytes with a private key.
     *
     * @param bytes Bytes to be signed.
     * @param masterPrivateKey Private key for computing the signature.
     * @return Signature for given data.
     * @throws InvalidKeyException In case invalid key was provided.
     * @throws SignatureException In case signature calculation fails.
     * @throws GenericCryptoException In case cryptography provider is incorrectly initialized.
     */
    public byte[] computeECDSASignature(byte[] bytes, PrivateKey masterPrivateKey) throws InvalidKeyException, SignatureException, GenericCryptoException {
        try {
            Signature ecdsa = Signature.getInstance("SHA256withECDSA", PowerAuthConfiguration.INSTANCE.getKeyConvertor().getProviderName());
            ecdsa.initSign(masterPrivateKey);
            ecdsa.update(bytes);
            return ecdsa.sign();
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Validate an ECDSA signature against given data using a public key.
     *
     * @param signedBytes Bytes that are signed.
     * @param signature Signature of the bytes.
     * @param masterPublicKey Public key for validating the signature.
     * @return Returns "true" if signature matches, "false" otherwise.
     * @throws InvalidKeyException In case invalid key was provided.
     * @throws SignatureException In case signature calculation fails.
     * @throws GenericCryptoException In case cryptography provider is incorrectly initialized.
     */
    public boolean validateECDSASignature(byte[] signedBytes, byte[] signature, PublicKey masterPublicKey) throws InvalidKeyException, SignatureException, GenericCryptoException {
        try {
            Signature ecdsa = Signature.getInstance("SHA256withECDSA", PowerAuthConfiguration.INSTANCE.getKeyConvertor().getProviderName());
            ecdsa.initVerify(masterPublicKey);
            ecdsa.update(signedBytes);
            return ecdsa.verify(signature);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Compute PowerAuth signature for given data using a secret signature keys and counter byte array.
     *
     * @param data Data to be signed.
     * @param signatureKeys Keys for computing the signature.
     * @param ctrData Counter byte array / derived key index.
     * @return PowerAuth signature for given data.
     * @throws GenericCryptoException In case signature computation fails.
     */
    public String computePowerAuthSignature(byte[] data, List<SecretKey> signatureKeys, byte[] ctrData) throws GenericCryptoException {
        // Prepare a hash
        HMACHashUtilities hmac = new HMACHashUtilities();

        // Prepare holder for signature components
        String[] signatureComponents = new String[signatureKeys.size()];

        CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

        for (int i = 0; i < signatureKeys.size(); i++) {
            byte[] signatureKey = keyConvertor.convertSharedSecretKeyToBytes(signatureKeys.get(i));
            byte[] derivedKey = hmac.hash(signatureKey, ctrData);

            for (int j = 0; j < i; j++) {
                byte[] signatureKeyInner = keyConvertor.convertSharedSecretKeyToBytes(signatureKeys.get(j + 1));
                byte[] derivedKeyInner = hmac.hash(signatureKeyInner, ctrData);
                derivedKey = hmac.hash(derivedKeyInner, derivedKey);
            }

            byte[] signatureLong = hmac.hash(derivedKey, data);

            if (signatureLong.length < 4) { // assert
                throw new IndexOutOfBoundsException();
            }
            int index = signatureLong.length - 4;
            int number = (ByteBuffer.wrap(signatureLong).getInt(index) & 0x7FFFFFFF) % (int) (Math.pow(10, PowerAuthConfiguration.SIGNATURE_LENGTH));
            String signature = String.format("%0" + PowerAuthConfiguration.SIGNATURE_LENGTH + "d", number);
            signatureComponents[i] = signature;
        }

        return Joiner.on("-").join(signatureComponents);
    }

    /**
     * Validate the PowerAuth signature for given data using provided keys.
     *
     * @param data Data that were signed.
     * @param signature Data signature.
     * @param signatureKeys Keys for signature validation.
     * @param ctrData Counter data.
     * @return Return "true" if signature matches, "false" otherwise.
     * @throws GenericCryptoException In case signature computation fails.
     */
    public boolean validatePowerAuthSignature(byte[] data, String signature, List<SecretKey> signatureKeys, byte[] ctrData) throws GenericCryptoException {
        return signature.equals(computePowerAuthSignature(data, signatureKeys, ctrData));
    }

}
