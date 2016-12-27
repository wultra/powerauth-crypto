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
package io.getlime.security.powerauth.app.server.service.exceptions;

import org.springframework.ws.soap.server.endpoint.annotation.FaultCode;
import org.springframework.ws.soap.server.endpoint.annotation.SoapFault;

/**
 * Exception for any SOAP interface error.
 *
 * @author Petr Dvorak
 */
@SoapFault(faultCode = FaultCode.SERVER)
public class GenericServiceException extends Exception {

    private static final long serialVersionUID = 7185138483623356230L;

    private String code;
    private String message;
    private String localizedMessage;

    /**
     * Constructor with error code and error message
     *
     * @param code             Error code
     * @param message          Error message
     * @param localizedMessage Localized error message
     */
    public GenericServiceException(String code, String message, String localizedMessage) {
        super();
        this.code = code;
        this.message = message;
        this.localizedMessage = localizedMessage;
    }

    /**
     * Get the error code
     *
     * @return Error code
     */
    public String getCode() {
        return code;
    }

    /**
     * Get the error message
     *
     * @param code Error message
     */
    public void setCode(String code) {
        this.code = code;
    }

    @Override
    public String getMessage() {
        return this.message;
    }

    @Override
    public String getLocalizedMessage() {
        return this.localizedMessage;
    }

}
