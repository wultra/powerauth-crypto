package io.getlime.security.service.util;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;

import io.getlime.security.powerauth.lib.config.PowerAuthConstants;
import io.getlime.security.powerauth.server.signature.PowerAuthServerSignature;

public class KeyUtil {
	
	public List<SecretKey> keysForSignatureType(String signatureType, SecretKey masterSecretKey, PowerAuthServerSignature powerAuthServerSignature) {
		
		List<SecretKey> signatureKeys = new ArrayList<>();
        
        if (signatureType.equals(PowerAuthConstants.SIGNATURE_TYPES.POSSESSION)) {
        	
        	SecretKey signatureKey = powerAuthServerSignature.generateServerSignaturePossessionKey(masterSecretKey);
        	signatureKeys.add(signatureKey);
        	
        } else if (signatureType.equals(PowerAuthConstants.SIGNATURE_TYPES.KNOWLEDGE)) {
        	
        	SecretKey signatureKey = powerAuthServerSignature.generateServerSignatureKnowledgeKey(masterSecretKey);
        	signatureKeys.add(signatureKey);
        	
        } else if (signatureType.equals(PowerAuthConstants.SIGNATURE_TYPES.BIOMETRY)) {
        	
        	SecretKey signatureKey = powerAuthServerSignature.generateServerSignatureBiometryKey(masterSecretKey);
        	signatureKeys.add(signatureKey);
        	
        } else if (signatureType.equals(PowerAuthConstants.SIGNATURE_TYPES.POSSESSION_KNOWLEDGE)) {
        	
        	SecretKey signatureKey = powerAuthServerSignature.generateServerSignaturePossessionKey(masterSecretKey);
        	signatureKeys.add(signatureKey);
        	signatureKey = powerAuthServerSignature.generateServerSignatureKnowledgeKey(masterSecretKey);
        	signatureKeys.add(signatureKey);
        	
        } else if (signatureType.equals(PowerAuthConstants.SIGNATURE_TYPES.POSSESSION_BIOMETRY)) {
        	
        	SecretKey signatureKey = powerAuthServerSignature.generateServerSignaturePossessionKey(masterSecretKey);
        	signatureKeys.add(signatureKey);
        	signatureKey = powerAuthServerSignature.generateServerSignatureBiometryKey(masterSecretKey);
        	signatureKeys.add(signatureKey);
        	
        } else if (signatureType.equals(PowerAuthConstants.SIGNATURE_TYPES.POSSESSION_KNOWLEDGE_BIOMETRY)) {
        	
        	SecretKey signatureKey = powerAuthServerSignature.generateServerSignaturePossessionKey(masterSecretKey);
        	signatureKeys.add(signatureKey);
        	signatureKey = powerAuthServerSignature.generateServerSignatureKnowledgeKey(masterSecretKey);
        	signatureKeys.add(signatureKey);
        	signatureKey = powerAuthServerSignature.generateServerSignatureBiometryKey(masterSecretKey);
        	signatureKeys.add(signatureKey);
        	
        }
        
        return signatureKeys;
        
	}

}
