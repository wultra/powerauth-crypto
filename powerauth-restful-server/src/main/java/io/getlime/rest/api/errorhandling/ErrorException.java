package io.getlime.rest.api.errorhandling;

import io.getlime.rest.api.model.ErrorModel;

import java.util.ArrayList;
import java.util.List;

/**
 * Exception with the list of associated errors.
 *
 * @author Petr Dvorak
 */
public class ErrorException extends Exception {

    private static final long serialVersionUID = 3441839878277238918L;

    private List<ErrorModel> errors;

    /**
     * Default constructor
     */
    public ErrorException() {
        super();
        this.errors = new ArrayList<>();
    }

    /**
     * Constructor with the list of errors to be associated with the exception.
     *
     * @param errors List of errors.
     */
    public ErrorException(List<ErrorModel> errors) {
        super();
        this.errors = errors;
    }

    /**
     * Get the error list.
     *
     * @return Error list.
     */
    public List<ErrorModel> getErrors() {
        return errors;
    }

}
