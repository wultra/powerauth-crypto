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
package io.getlime.rest.jaxrs.api.security.authentication;

import io.getlime.rest.api.security.authentication.PowerAuthApiAuthentication;

import java.io.Serializable;

/**
 * PowerAuth API authentication object used between intermediate server application (such as mobile 
 * banking API) and core systems (such as banking core).
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthApiAuthenticationImpl implements PowerAuthApiAuthentication, Serializable {

    private static final long serialVersionUID = -1270504081898389806L;

    private String activationId;
    private String userId;

    /**
     * Default constructor
     */
    public PowerAuthApiAuthenticationImpl() {
    }

    /**
     * Constructor for a new PowerAuthApiAuthenticationImpl
     * @param activationId Activation ID
     * @param userId User ID
     */
    public PowerAuthApiAuthenticationImpl(String activationId, String userId) {
        this.activationId = activationId;
        this.userId = userId;
    }

    /**
     * Get user ID
     * @return User ID
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Set user ID
     * @param userId User ID
     */
    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * Get activation ID
     * @return Activation ID
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID
     * @param activationId Activation ID
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

}
