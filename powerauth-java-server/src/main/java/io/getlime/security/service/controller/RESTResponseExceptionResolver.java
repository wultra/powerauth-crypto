package io.getlime.security.service.controller;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.Ordered;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.DefaultHandlerExceptionResolver;

import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class RESTResponseExceptionResolver extends DefaultHandlerExceptionResolver {

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
