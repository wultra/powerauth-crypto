/*
 * PowerAuth Crypto Library
 * Copyright 2023 Wultra s.r.o.
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
package io.getlime.security.powerauth.crypto.lib.config;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;

/**
 * Configuration for decimal signatures.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class DecimalSignatureConfiguration extends SignatureConfiguration {

    private Integer length;

    /**
     * Constructor with the decimal signature. Package scoped.
     */
    DecimalSignatureConfiguration() {
        super(PowerAuthSignatureFormat.DECIMAL);
    }

    /**
     * Constructor with signature length. Package scoped.
     *
     * @param length Length.
     */
    DecimalSignatureConfiguration(Integer length) {
        super(PowerAuthSignatureFormat.DECIMAL);
        this.length = length;
    }

    /**
     * Get length of signature.
     *
     * @return Length of signature.
     */
    public Integer getLength() {
        return length;
    }

    /**
     * Set length of the signature.
     *
     * @param length Length of signature.
     */
    public void setLength(Integer length) {
        this.length = length;
    }
}
