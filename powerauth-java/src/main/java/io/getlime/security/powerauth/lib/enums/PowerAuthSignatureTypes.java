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