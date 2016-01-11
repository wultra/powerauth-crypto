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
package io.getlime.security.powerauth.lib.enums;

import java.util.HashMap;
import java.util.Map;

public enum PowerAuthSignatureTypes {
	
	POSSESSION("possession"),
	KNOWLEDGE("knowledge"),
	BIOMETRY("biometry"),
	POSSESSION_KNOWLEDGE("possession_knowledge"),
	POSSESSION_BIOMETRY("possession_biometry"),
	POSSESSION_KNOWLEDGE_BIOMETRY("possession_knowledge_biometry");
	
	private String value;
	
	private static Map<String, PowerAuthSignatureTypes> map = new HashMap<>();

    static {
        for (PowerAuthSignatureTypes type : PowerAuthSignatureTypes.values()) {
            map.put(type.value, type);
        }
    }
    
    private PowerAuthSignatureTypes(final String value) {
    	this.value = value;
    }

    public static PowerAuthSignatureTypes getEnumFromString(String value) {
    	PowerAuthSignatureTypes type = map.get(value);
    	if (type == null) { // try to guess the most usual suspect...
    		return PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE;
    	} else {
    		return type;
    	}
    }

    public boolean equalsName(String otherName) {
        return (otherName == null) ? false : value.equals(otherName);
    }
    
    public String toString() {
        return this.value;
     }

}