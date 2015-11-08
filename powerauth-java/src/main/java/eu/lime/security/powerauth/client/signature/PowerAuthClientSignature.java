package eu.lime.security.powerauth.client.signature;

import eu.lime.security.powerauth.lib.generator.KeyGenerator;
import eu.lime.security.powerauth.lib.util.SignatureUtils;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

public class PowerAuthClientSignature {
    
    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final SignatureUtils signatureUtils = new SignatureUtils();
    
    public SecretKey generateMasterSignatureKey(
            PrivateKey devicePrivateKey, 
            PublicKey serverPublicKey) throws InvalidKeyException {
        return keyGenerator.computeSharedKey(devicePrivateKey, serverPublicKey);
    }
    
    public SecretKey generateDerivedSignatureKey(SecretKey masterSignatureKey) {
        return keyGenerator.deriveSecretKey(masterSignatureKey, new Long(1));
    }
    
    public byte[] signatureForData(
            byte[] data,
            SecretKey signatureKey,
            Long ctr) throws InvalidKeyException {
        return signatureUtils.computePowerAuthSignature(data, signatureKey, ctr);
    }
    
}
