/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.crypto.lib.enums;

import java.util.HashMap;
import java.util.Map;

/**
 * Enum with signature type values.
 *
 * @author Petr Dvorak
 *
 */
public enum PowerAuthSignatureTypes {

    /**
     * 1FA signature using possession factor key, value = "possession"
     */
    POSSESSION("possession"),

    /**
     * 1FA signature using knowledge factor key, value = "knowledge"
     */
    KNOWLEDGE("knowledge"),

    /**
     * 1FA signature using biometry factor key, value = "biometry"
     */
    BIOMETRY("biometry"),

    /**
     * 2FA signature using possession and knowledge factor key, value = "possession_knowledge"
     */
    POSSESSION_KNOWLEDGE("possession_knowledge"),

    /**
     * 2FA signature using possession and biometry factor key, value = "possession_biometry"
     */
    POSSESSION_BIOMETRY("possession_biometry"),

    /**
     * 3FA signature using possession, knowledge and biometry factor key, value = "possession_knowledge_biometry"
     */
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

    /**
     * Get enum value from provided string. In case the provided value does not match any value, POSSESSION_KNOWLEDGE is returned.
     * @param value String to get the enum value for.
     * @return Enum value.
     */
    public static PowerAuthSignatureTypes getEnumFromString(String value) {
        PowerAuthSignatureTypes type = map.get(value);
        if (type == null) { // try to guess the most usual suspect...
            return PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE;
        } else {
            return type;
        }
    }

    /**
     * Check if the enum value has the same name as a given string.
     * @param otherName Name to be checked.
     * @return True in case of enum value is equal to provided name.
     */
    public boolean equalsName(String otherName) {
        return (otherName == null) ? false : value.equals(otherName);
    }

    @Override
    public String toString() {
        return this.value;
    }

}