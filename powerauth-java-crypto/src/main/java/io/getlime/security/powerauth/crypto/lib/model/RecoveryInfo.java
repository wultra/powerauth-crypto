/*
 * PowerAuth Crypto Library
 * Copyright 2019 Wultra s.r.o.
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
package io.getlime.security.powerauth.crypto.lib.model;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Class representing recovery code, recovery PUKs and optional seed information.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class RecoveryInfo {

    private String recoveryCode;
    private Map<Integer, String> puks = new LinkedHashMap<>();
    private RecoverySeed seed;

    /**
     * Default contructor.
     */
    public RecoveryInfo() {
    }

    /**
     * Constructor with recovery code and PUKs.
     * @param recoveryCode Recovery code.
     * @param puks PUKs.
     */
    public RecoveryInfo(String recoveryCode, Map<Integer, String> puks) {
        this.recoveryCode = recoveryCode;
        this.puks = new LinkedHashMap<>(puks);
    }

    /**
     * Constructor with recovery code, PUKs and seed.
     * @param recoveryCode Recovery code.
     * @param puks Recovery PUKs.
     * @param seed Recovery seed.
     */
    public RecoveryInfo(String recoveryCode, Map<Integer, String> puks, RecoverySeed seed) {
        this.recoveryCode = recoveryCode;
        this.puks = new LinkedHashMap<>(puks);
        this.seed = seed;
    }

    /**
     * Get recovery code.
     * @return Recovery code.
     */
    public String getRecoveryCode() {
        return recoveryCode;
    }

    /**
     * Set recovery code.
     * @param recoveryCode Recovery code.
     */
    public void setRecoveryCode(String recoveryCode) {
        this.recoveryCode = recoveryCode;
    }

    /**
     * Get recovery PUKs.
     * @return Recovery PUKs.
     */
    public Map<Integer, String> getPuks() {
        return new LinkedHashMap<>(puks);
    }

    /**
     * Set recovery PUKs.
     * @param puks Recovery PUKs.
     */
    public void setPuks(Map<Integer, String> puks) {
        this.puks = new LinkedHashMap<>(puks);
    }

    /**
     * Get recovery seed.
     * @return Recovery seed.
     */
    public RecoverySeed getSeed() {
        return seed;
    }

    /**
     * Set recovery seed.
     * @param seed Recovery seed.
     */
    public void setSeed(RecoverySeed seed) {
        this.seed = seed;
    }

}
