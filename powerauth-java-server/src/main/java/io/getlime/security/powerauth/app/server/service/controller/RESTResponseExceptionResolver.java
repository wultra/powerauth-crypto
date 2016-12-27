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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.Ordered;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.DefaultHandlerExceptionResolver;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;

/**
 * Exception resolver responsible for catching Spring errors and rendering them in
 * the same format as the application logics exceptions.
 *
 * @author Petr Dvorak
 */
@Component
public class RESTResponseExceptionResolver extends DefaultHandlerExceptionResolver {

    /**
     * Default constructor.
     */
    public RESTResponseExceptionResolver() {
        super.setOrder(Ordered.LOWEST_PRECEDENCE - 1);
    }

    @Override
    protected ModelAndView doResolveException(HttpServletRequest request, HttpServletResponse response, Object handler, Exception exception) {
        try {
            // Build the error list
            RESTErrorModel error = new RESTErrorModel();
            error.setCode("ERR_SPRING_JAVA");
            error.setMessage(exception.getMessage());
            error.setLocalizedMessage(exception.getLocalizedMessage());
            List<RESTErrorModel> errorList = new LinkedList<>();
            errorList.add(error);

            // Prepare the response
            RESTResponseWrapper<List<RESTErrorModel>> errorResponse = new RESTResponseWrapper<>("ERROR", errorList);

            // Write the response in JSON and send it
            ObjectMapper mapper = new ObjectMapper();
            String responseString = mapper.writeValueAsString(errorResponse);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getOutputStream().print(responseString);
            response.flushBuffer();
        } catch (IOException e) {
            // Response object does have an output stream here
        }
        return new ModelAndView();
    }

}
