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

import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class used for handling RESTful service errors.
 *
 * @author Petr Dvorak
 */
@ControllerAdvice
public class RESTControllerAdvice {

    /**
     * Handle all service exceptions using the same error format. Response has a status code 400 Bad Request.
     *
     * @param e   Service exception.
     * @return REST response with error collection.
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = GenericServiceException.class)
    public @ResponseBody RESTResponseWrapper<List<RESTErrorModel>> returnGenericError(GenericServiceException e) {
        RESTErrorModel error = new RESTErrorModel();
        error.setCode(e.getCode());
        error.setMessage(e.getMessage());
        error.setLocalizedMessage(e.getLocalizedMessage());
        List<RESTErrorModel> errorList = new LinkedList<>();
        errorList.add(error);
        Logger.getLogger(RESTControllerAdvice.class.getName()).log(Level.SEVERE, null, e);
        return new RESTResponseWrapper<>("ERROR", errorList);
    }

}
