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
package io.getlime.security.powerauth.app.server.service.controller;

/**
 * Class representing an error returned by RESTful API
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class RESTErrorModel {

    private String code;
    private String message;
    private String localizedMessage;

    /**
     * Get error code.
     *
     * @return Error code.
     */
    public String getCode() {
        return code;
    }

    /**
     * Set error code.
     *
     * @param code Error code.
     */
    public void setCode(String code) {
        this.code = code;
    }

    /**
     * Get message (not localized).
     *
     * @return Message.
     */
    public String getMessage() {
        return message;
    }

    /**
     * Set message (not localized).
     *
     * @param message Message.
     */
    public void setMessage(String message) {
        this.message = message;
    }

    /**
     * Get localized message.
     *
     * @return Localized message.
     */
    public String getLocalizedMessage() {
        return localizedMessage;
    }

    /**
     * Set localized message.
     *
     * @param localizedMessage Localized message.
     */
    public void setLocalizedMessage(String localizedMessage) {
        this.localizedMessage = localizedMessage;
    }

}
