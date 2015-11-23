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
