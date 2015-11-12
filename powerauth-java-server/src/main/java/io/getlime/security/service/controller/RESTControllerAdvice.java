package io.getlime.security.service.controller;

import java.util.LinkedList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import io.getlime.security.service.exceptions.GenericServiceException;

@ControllerAdvice
public class RESTControllerAdvice {
		
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ExceptionHandler(value = GenericServiceException.class)
	public @ResponseBody RESTResponseWrapper<List<RESTErrorModel>> returnGenericError(HttpServletRequest req, GenericServiceException e) {
		RESTErrorModel error = new RESTErrorModel();
		error.setCode(e.getCode());
		error.setMessage(e.getMessage());
		error.setLocalizedMessage(e.getLocalizedMessage());
		List<RESTErrorModel> errorList = new LinkedList<RESTErrorModel>();
		errorList.add(error);
		return new RESTResponseWrapper<List<RESTErrorModel>>("ERROR", errorList);
	}

}
