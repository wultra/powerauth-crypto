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
package io.getlime.security.powerauth.app.rest.api.spring.errorhandling;

import io.getlime.core.rest.model.base.entity.Error;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.core.rest.model.base.response.Response;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Implementation of a default exception handler for the demo server.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
@ControllerAdvice
public class DefaultExceptionHandler {

    /**
     * Handle Exception exceptions.
     * @param exception Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = Exception.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handleException(Exception exception) {
        Logger.getLogger(DefaultExceptionHandler.class.getName()).log(Level.SEVERE, exception.getMessage(), exception);
        Error error = new Error("ERR_GENERIC", exception.getMessage());
        return new ErrorResponse(error);
    }

}
