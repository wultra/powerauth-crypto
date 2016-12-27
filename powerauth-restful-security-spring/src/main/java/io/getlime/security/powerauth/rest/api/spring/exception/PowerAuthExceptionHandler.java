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
package io.getlime.security.powerauth.rest.api.spring.exception;

import io.getlime.security.powerauth.rest.api.model.base.PowerAuthApiResponse;
import io.getlime.security.powerauth.rest.api.model.entity.ErrorModel;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthSecureVaultException;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Implementation of a PA2.0 Standard RESTful API exception handler.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
@ControllerAdvice
@Order(PowerAuthExceptionHandler.PRECEDENCE)
public class PowerAuthExceptionHandler {

    public static final int PRECEDENCE = -100;

    /**
     * Handle PowerAuthAuthenticationException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthAuthenticationException.class)
    @ResponseStatus(value = HttpStatus.UNAUTHORIZED)
    public @ResponseBody PowerAuthApiResponse<ErrorModel> handleUnauthorizedException(Exception ex) {
        PowerAuthAuthenticationException paex = (PowerAuthAuthenticationException)ex;
        Logger.getLogger(PowerAuthExceptionHandler.class.getName()).log(Level.SEVERE, paex.getMessage(), paex);
        ErrorModel error = new ErrorModel(paex.getDefaultCode(), paex.getMessage());
        return new PowerAuthApiResponse<>(PowerAuthApiResponse.Status.ERROR, error);
    }

    /**
     * Handle PowerAuthActivationException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthActivationException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody PowerAuthApiResponse<ErrorModel> handleActivationException(Exception ex) {
        PowerAuthActivationException paex = (PowerAuthActivationException)ex;
        Logger.getLogger(PowerAuthExceptionHandler.class.getName()).log(Level.SEVERE, paex.getMessage(), paex);
        ErrorModel error = new ErrorModel(paex.getDefaultCode(), paex.getMessage());
        return new PowerAuthApiResponse<>(PowerAuthApiResponse.Status.ERROR, error);
    }

    /**
     * Handle PowerAuthSecureVaultException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthSecureVaultException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody PowerAuthApiResponse<ErrorModel> handleSecureVaultException(Exception ex) {
        PowerAuthSecureVaultException paex = (PowerAuthSecureVaultException)ex;
        Logger.getLogger(PowerAuthExceptionHandler.class.getName()).log(Level.SEVERE, paex.getMessage(), paex);
        ErrorModel error = new ErrorModel(paex.getDefaultCode(), paex.getMessage());
        return new PowerAuthApiResponse<>(PowerAuthApiResponse.Status.ERROR, error);
    }

}
