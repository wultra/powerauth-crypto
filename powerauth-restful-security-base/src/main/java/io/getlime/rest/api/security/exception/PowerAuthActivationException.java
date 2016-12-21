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
package io.getlime.rest.api.security.exception;

/**
 * Exception related to processes during a new activation process.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PowerAuthActivationException extends Exception {

    private static final long serialVersionUID = -7975115359211508795L;

    private static final String DEFAULT_CODE = "ERR_ACTIVATION";
    private static final String DEFAULT_ERROR = "POWER_AUTH_ACTIVATION_INVALID";

    /**
     * Default constructor
     */
    public PowerAuthActivationException() {
        super(DEFAULT_ERROR);
    }

    /**
     * Constructor with a custom error message
     * @param message Error message
     */
    public PowerAuthActivationException(String message) {
        super(message);
    }

    /**
     * Get default error code, used for example in the REST response.
     * @return Default error code.
     */
    public String getDefaultCode() {
        return DEFAULT_CODE;
    }
}
