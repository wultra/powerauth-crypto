package com.wultra.security.powerauth.crypto.lib.v4.ml;

import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.PqcKem;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;

/**
 * ML-KEM implementation of the post-quantum key encapsulation mechanism.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class MlKem implements PqcKem {

    private final MLKEMParameterSpec kemParameterSpec;

    /**
     * Construct with default parameter spec (ml_kem_768).
     */
    public MlKem() {
        this.kemParameterSpec = MLKEMParameterSpec.ml_kem_768;
    }

    /**
     * Construct with a specific parameter spec.
     * @param kemParameterSpec Algorithm parameter spec.
     * @throws GenericCryptoException In case of missing parameter specification.
     */
    public MlKem(MLKEMParameterSpec kemParameterSpec) throws GenericCryptoException {
        if (kemParameterSpec == null) {
            throw new GenericCryptoException("Missing ML-KEM parameter specification");
        }
        this.kemParameterSpec = kemParameterSpec;
    }

    @Override
    public KeyPair generateKeyPair() throws GenericCryptoException {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ML-KEM", "BC");
            keyPairGenerator.initialize(kemParameterSpec);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new GenericCryptoException("Error generating key pair", e);
        }
    }

    @Override
    public SecretKeyWithEncapsulation encapsulate(PublicKey encapsulationKey) throws GenericCryptoException {
        if (encapsulationKey == null) {
            throw new GenericCryptoException("Missing public key during encapsulation");
        }
        try {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance("ML-KEM", "BC");
            keyGenerator.init(new KEMGenerateSpec.Builder(encapsulationKey, "RAW", 256).withNoKdf().build());
            return (SecretKeyWithEncapsulation) keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new GenericCryptoException("Error during encapsulation", e);
        }
    }

    @Override
    public SecretKey decapsulate(PrivateKey decapsulationKey, byte[] ciphertext) throws GenericCryptoException {
        if (decapsulationKey == null) {
            throw new GenericCryptoException("Missing public key during decapsulation");
        }
        if (ciphertext == null) {
            throw new GenericCryptoException("Missing ciphertext during decapsulation");
        }
        try {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance("ML-KEM", "BC");
            keyGenerator.init(new KEMExtractSpec.Builder(decapsulationKey, ciphertext, "RAW", 256).withNoKdf().build());
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new GenericCryptoException("Error during decapsulation", e);
        }
    }

}
