package io.getlime.security.service.exceptions;

import org.springframework.ws.soap.server.endpoint.annotation.FaultCode;
import org.springframework.ws.soap.server.endpoint.annotation.SoapFault;

@SoapFault(faultCode = FaultCode.SERVER)
public class GenericServiceException extends Exception {

    private static final long serialVersionUID = 7185138483623356230L;

    private String code;

    public GenericServiceException(String message) {
        super(message);
        this.code = "GENERIC";
    }

    public GenericServiceException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

}
