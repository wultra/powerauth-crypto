package io.getlime.security.service.exceptions;

import org.springframework.ws.soap.server.endpoint.annotation.FaultCode;
import org.springframework.ws.soap.server.endpoint.annotation.SoapFault;

@SoapFault(faultCode = FaultCode.SERVER)
public class GenericServiceException extends Exception {

	private static final long serialVersionUID = 7185138483623356230L;

}
