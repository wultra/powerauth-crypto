package eu.lime.security.powerauth.server.signature;

import eu.lime.security.powerauth.lib.generator.KeyGenerator;
import eu.lime.security.powerauth.lib.util.SignatureUtils;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

public class PowerAuthServerSignature {
    
    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final SignatureUtils signatureUtils = new SignatureUtils();
    
    public SecretKey generateMasterSignatureKey(
            PrivateKey serverPrivateKey, 
            PublicKey devicePublicKey) throws InvalidKeyException {
        return keyGenerator.computeSharedKey(serverPrivateKey, devicePublicKey);
    }
    
    public SecretKey generateDerivedSignatureKey(SecretKey masterSignatureKey) {
        return keyGenerator.deriveSecretKey(masterSignatureKey, new Long(1));
    }
    
    public boolean verifySignatureForData(
            byte[] data,
            byte[] signature,
            SecretKey signatureKey,
            Long ctr) throws InvalidKeyException {
        return signatureUtils.validatePowerAuthSignature(data, signature, signatureKey, ctr);
    }
    
}
