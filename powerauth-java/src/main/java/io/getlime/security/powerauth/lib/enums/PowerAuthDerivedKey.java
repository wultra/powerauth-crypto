package io.getlime.security.powerauth.lib.enums;

import java.util.HashMap;
import java.util.Map;

public enum PowerAuthDerivedKey {
	
	SIGNATURE_POSSESSION(1),
	SIGNATURE_KNOWLEDGE(2),
	SIGNATURE_BIOMETRY(3),
	TRANSPORT(1000),
	ENCRYPTED_VAULT(2000);
	
	private long index;

    private static Map<Long, PowerAuthDerivedKey> map = new HashMap<>();

    static {
        for (PowerAuthDerivedKey derivedKey : PowerAuthDerivedKey.values()) {
            map.put(derivedKey.index, derivedKey);
        }
    }

    private PowerAuthDerivedKey(final long index) {
    	this.index = index;
    }

    public static PowerAuthDerivedKey valueOf(long index) {
        return map.get(index);
    }
    
    public long getIndex() {
    	return index;
    }

}