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

package io.getlime.rest.api.model.entity;

/**
 * Transport object representing an error instance.
 *
 * @author Petr Dvorak
 */
public class ErrorModel {

    private String code;
    private String message;

    /**
     * Constructor accepting code and message.
     *
     * @param code    Error code.
     * @param message Error message.
     */
    public ErrorModel(String code, String message) {
        super();
        this.code = code;
        this.message = message;
    }

    /**
     * Get error message.
     *
     * @return Error message.
     */
    public String getMessage() {
        return message;
    }

    /**
     * Set error message.
     *
     * @param message Error message.
     */
    public void setMessage(String message) {
        this.message = message;
    }

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
     * Get localized error message.
     *
     * @return Localized error message.
     */
    public String getLocalizedMessage() {
        //TODO: Implement better
        return message;
    }

}