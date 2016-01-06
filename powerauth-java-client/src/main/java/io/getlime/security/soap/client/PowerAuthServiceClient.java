package io.getlime.security.soap.client;

import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.springframework.ws.client.core.support.WebServiceGatewaySupport;

import io.getlime.powerauth.soap.BlockActivationRequest;
import io.getlime.powerauth.soap.BlockActivationResponse;
import io.getlime.powerauth.soap.CommitActivationRequest;
import io.getlime.powerauth.soap.CommitActivationResponse;
import io.getlime.powerauth.soap.GetActivationListForUserRequest;
import io.getlime.powerauth.soap.GetActivationListForUserResponse;
import io.getlime.powerauth.soap.GetActivationListForUserResponse.Activations;
import io.getlime.powerauth.soap.GetActivationStatusRequest;
import io.getlime.powerauth.soap.GetActivationStatusResponse;
import io.getlime.powerauth.soap.InitActivationRequest;
import io.getlime.powerauth.soap.InitActivationResponse;
import io.getlime.powerauth.soap.PrepareActivationRequest;
import io.getlime.powerauth.soap.PrepareActivationResponse;
import io.getlime.powerauth.soap.RemoveActivationRequest;
import io.getlime.powerauth.soap.RemoveActivationResponse;
import io.getlime.powerauth.soap.SignatureAuditRequest;
import io.getlime.powerauth.soap.SignatureAuditResponse;
import io.getlime.powerauth.soap.UnblockActivationRequest;
import io.getlime.powerauth.soap.UnblockActivationResponse;
import io.getlime.powerauth.soap.VaultUnlockRequest;
import io.getlime.powerauth.soap.VaultUnlockResponse;
import io.getlime.powerauth.soap.VerifySignatureRequest;
import io.getlime.powerauth.soap.VerifySignatureResponse;

public class PowerAuthServiceClient extends WebServiceGatewaySupport {
	
	public InitActivationResponse initActivation(InitActivationRequest request) {
		return (InitActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	public InitActivationResponse initActivation(String userId) {
		InitActivationRequest request = new InitActivationRequest();
		request.setUserId(userId);
		return this.initActivation(request);
	}
	
	public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) {
		return (PrepareActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	public PrepareActivationResponse prepareActivation(String activationIdShort, String activationName, String activationNonce, String cDevicePublicKey, String extras) {
		PrepareActivationRequest request = new PrepareActivationRequest();
		request.setActivationIdShort(activationIdShort);
		request.setActivationName(activationName);
		request.setActivationNonce(activationNonce);
		request.setCDevicePublicKey(cDevicePublicKey);
		request.setExtras(extras);
		return this.prepareActivation(request);
	}
	
	public CommitActivationResponse commitActivation(CommitActivationRequest request) {
		return (CommitActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	public CommitActivationResponse commitActivation(String activationId) {
		CommitActivationRequest request = new CommitActivationRequest();
		request.setActivationId(activationId);
		return this.commitActivation(request);
	}
	
	public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) {
		return (GetActivationStatusResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	public GetActivationStatusResponse getActivationStatus(String activationId) {
		GetActivationStatusRequest request = new GetActivationStatusRequest();
		request.setActivationId(activationId);
		return this.getActivationStatus(request);
	}
	
	public GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) {
		return (GetActivationListForUserResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	public List<Activations> getActivationListForUser(String userId) {
		GetActivationListForUserRequest request = new GetActivationListForUserRequest();
		request.setUserId(userId);
		return this.getActivationListForUser(request).getActivations();
	}
	
	public RemoveActivationResponse removeActivation(RemoveActivationRequest request) {
		return (RemoveActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	public RemoveActivationResponse removeActivation(String activationId) {
		RemoveActivationRequest request = new RemoveActivationRequest();
		request.setActivationId(activationId);
		return this.removeActivation(request);
	}
	
	public BlockActivationResponse blockActivation(BlockActivationRequest request) {
		return (BlockActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	public BlockActivationResponse blockActivation(String activationId) {
		BlockActivationRequest request = new BlockActivationRequest();
		request.setActivationId(activationId);
		return this.blockActivation(request);
	}
	
	public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) {
		return (UnblockActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	public UnblockActivationResponse unblockActivation(String activationId) {
		UnblockActivationRequest request = new UnblockActivationRequest();
		request.setActivationId(activationId);
		return this.unblockActivation(request);
	}
	
	public VaultUnlockResponse unlockVault(VaultUnlockRequest request) {
		return (VaultUnlockResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	public VaultUnlockResponse unlockVault(String activationId, String signature, String signatureType) {
		VaultUnlockRequest request = new VaultUnlockRequest();
		request.setActivationId(activationId);
		request.setSignature(signature);
		request.setSignatureType(signatureType);
		return this.unlockVault(request);
	}
	
	public VerifySignatureResponse verifySignature(VerifySignatureRequest request) {
		return (VerifySignatureResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	public VerifySignatureResponse verifySignature(String activationId, String data, String signature, String signatureType) {
		VerifySignatureRequest request = new VerifySignatureRequest();
		request.setActivationId(activationId);
		request.setData(data);
		request.setSignature(signature);
		request.setSignatureType(signatureType);
		return this.verifySignature(request);
	}
	
	private XMLGregorianCalendar calendarWithDate(Date date) throws DatatypeConfigurationException {
    	GregorianCalendar c = new GregorianCalendar();
    	c.setTime(date);
    	XMLGregorianCalendar date2 = DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
    	return date2;
    }
	
	public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) {
		return (SignatureAuditResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	public List<SignatureAuditResponse.Items> getSignatureAuditLog(String userId, Date startingDate, Date endingDate) throws DatatypeConfigurationException {
		SignatureAuditRequest request = new SignatureAuditRequest();
		request.setUserId(userId);
		request.setTimestampFrom(calendarWithDate(startingDate));
		request.setTimestampTo(calendarWithDate(endingDate));
		return this.getSignatureAuditLog(request).getItems();
	}

}
