package io.getlime.rest.api.errorhandling;

import java.util.List;

import io.getlime.rest.api.model.ErrorModel;

public class ErrorException extends Exception {

	private static final long serialVersionUID = 3441839878277238918L;
	
	private List<ErrorModel> errors;
	
	public ErrorException(List<ErrorModel> errors) {
		super();
		this.errors = errors;
	}
	
	public List<ErrorModel> getErrors() {
		return errors;
	}

}
