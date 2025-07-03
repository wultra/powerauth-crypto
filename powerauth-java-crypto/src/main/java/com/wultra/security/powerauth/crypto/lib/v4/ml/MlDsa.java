package com.wultra.security.powerauth.crypto.lib.v4.ml;

import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.PqcDsa;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

import java.security.*;

/**
 * ML-DSA implementation of the post-quantum digital signature algorithm.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class MlDsa implements PqcDsa {


    private final MLDSAParameterSpec dsaParameterSpec;

    /**
     * Construct with default parameter spec (ml_dsa_65).
     */
    public MlDsa() {
        this.dsaParameterSpec = MLDSAParameterSpec.ml_dsa_65;
    }

    /**
     * Construct with a specific parameter spec.
     * @param dsaParameterSpec Algorithm parameter spec.
     * @throws GenericCryptoException In case of missing parameter specification.
     */
    public MlDsa(MLDSAParameterSpec dsaParameterSpec) throws GenericCryptoException {
        if (dsaParameterSpec == null) {
            throw new GenericCryptoException("Missing ML-DSA parameter specification");
        }
        this.dsaParameterSpec = dsaParameterSpec;
    }

    @Override
    public KeyPair generateKeyPair() throws CryptoProviderException {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("MLDSA", "BC");
            keyPairGenerator.initialize(dsaParameterSpec);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new CryptoProviderException("Error generating key pair", e);
        }
    }

    @Override
    public byte[] sign(PrivateKey privateKey, byte[] message) throws GenericCryptoException {
        if (privateKey == null) {
            throw new GenericCryptoException("Missing private key when signing a message");
        }
        if (message == null) {
            throw new GenericCryptoException("Missing message to sign");
        }
        try {
            final Signature mlDsa = Signature.getInstance("MLDSA", "BC");
            mlDsa.initSign(privateKey);
            mlDsa.update(message);
            return mlDsa.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            throw new GenericCryptoException("Error during signature calculation", e);
        }
    }

    @Override
    public boolean verify(PublicKey publicKey, byte[] message, byte[] signature) throws GenericCryptoException {
        if (publicKey == null) {
            throw new GenericCryptoException("Missing public key when verifying a signature");
        }
        if (message == null) {
            throw new GenericCryptoException("Missing message when verifying a signature");
        }
        if (signature == null) {
            throw new GenericCryptoException("Missing signature to verify");
        }
        try {
            final Signature mlDsa = Signature.getInstance("MLDSA", "BC");
            mlDsa.initVerify(publicKey);
            mlDsa.update(message);
            return mlDsa.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            throw new GenericCryptoException("Error during signature verification", e);
        }
    }
}
