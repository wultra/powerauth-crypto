package io.getlime.rest.api.sample;

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
	public @ResponseBody PowerAuthAPIResponse<ErrorBody> handleUnauthorizedException(HttpServletRequest request, Exception exception) {
		exception.printStackTrace();
		return new PowerAuthAPIResponse<DefaultExceptionHandler.ErrorBody>("ERROR", new ErrorBody(exception.getMessage()));
	}
	
	@ExceptionHandler(value = Exception.class)
	@ResponseStatus(value = HttpStatus.BAD_REQUEST)
	public @ResponseBody PowerAuthAPIResponse<ErrorBody> handleException(HttpServletRequest request, Exception exception) {
		exception.printStackTrace();
		return new PowerAuthAPIResponse<DefaultExceptionHandler.ErrorBody>("ERROR", new ErrorBody(exception.getMessage()));
	}

}
