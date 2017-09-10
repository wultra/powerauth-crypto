package io.getlime.security.powerauth.http.validator;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class InvalidPowerAuthHttpHeaderException extends Throwable {

    public InvalidPowerAuthHttpHeaderException(String message) {
        super(message);
    }
}
