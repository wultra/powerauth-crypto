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
package com.wultra.security.powerauth.crypto.lib.config;

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthAuthenticationCodeFormat;

/**
 * Configuration for decimal authentication codes.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class DecimalAuthenticationCodeConfiguration extends AuthenticationCodeConfiguration {

    private Integer length;

    /**
     * Constructor with the decimal authentication codes. Package scoped.
     */
    DecimalAuthenticationCodeConfiguration() {
        super(PowerAuthAuthenticationCodeFormat.DECIMAL);
    }

    /**
     * Constructor with authentication code length. Package scoped.
     *
     * @param length Length.
     */
    DecimalAuthenticationCodeConfiguration(Integer length) {
        super(PowerAuthAuthenticationCodeFormat.DECIMAL);
        this.length = length;
    }

    /**
     * Get length of authentication code.
     *
     * @return Length of authentication code.
     */
    public Integer getLength() {
        return length;
    }

    /**
     * Set length of the authentication code.
     *
     * @param length Length of authentication code.
     */
    public void setLength(Integer length) {
        this.length = length;
    }
}
