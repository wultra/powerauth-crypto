package io.getlime.rest.api.errorhandling;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import io.getlime.rest.api.model.PowerAuthAPIResponse;
import io.getlime.rest.api.security.exception.PowerAuthAuthenticationException;

@ControllerAdvice
public class DefaultExceptionHandler {

	class ErrorBody {

		private String message;

		public ErrorBody(String message) {
			super();
			this.message = message;
		}

		public String getMessage() {
			return message;
		}

		public void setMessage(String message) {
			this.message = message;
		}

	}

	@ExceptionHandler(value = PowerAuthAuthenticationException.class)
	@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
	public @ResponseBody PowerAuthAPIResponse<List<ErrorBody>> handleUnauthorizedException(HttpServletRequest request, Exception exception) {
		exception.printStackTrace();
		List<ErrorBody> errorList = new ArrayList<>();
		errorList.add(new ErrorBody(exception.getMessage()));
		return new PowerAuthAPIResponse<List<ErrorBody>>("ERROR", errorList);
	}

	@ExceptionHandler(value = Exception.class)
	@ResponseStatus(value = HttpStatus.BAD_REQUEST)
	public @ResponseBody PowerAuthAPIResponse<List<ErrorBody>> handleException(HttpServletRequest request, Exception exception) {
		exception.printStackTrace();
		List<ErrorBody> errorList = new ArrayList<>();
		errorList.add(new ErrorBody(exception.getMessage()));
		return new PowerAuthAPIResponse<List<ErrorBody>>("ERROR", errorList);
	}

}
