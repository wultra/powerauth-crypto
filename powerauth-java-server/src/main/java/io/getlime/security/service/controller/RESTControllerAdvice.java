/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.getlime.security.service.controller;

import io.getlime.security.service.exceptions.GenericServiceException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import javax.servlet.http.HttpServletRequest;
import java.util.LinkedList;
import java.util.List;

/**
 * Class used for handling RESTful service errors.
 *
 * @author Petr Dvorak
 */
@ControllerAdvice
public class RESTControllerAdvice {

    /**
     * Handle all exceptions using the same error format. Response has a status code 400 Bad Request.
     *
     * @param req Underlying HttpServletRequest.
     * @param e   Service exception.
     * @return REST response with error collection.
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = GenericServiceException.class)
    public @ResponseBody RESTResponseWrapper<List<RESTErrorModel>> returnGenericError(HttpServletRequest req, GenericServiceException e) {
        RESTErrorModel error = new RESTErrorModel();
        error.setCode(e.getCode());
        error.setMessage(e.getMessage());
        error.setLocalizedMessage(e.getLocalizedMessage());
        List<RESTErrorModel> errorList = new LinkedList<>();
        errorList.add(error);
        return new RESTResponseWrapper<>("ERROR", errorList);
    }

}
