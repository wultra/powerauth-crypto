/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
	
	/**
	 * Convert date to XMLGregorianCalendar
	 * @param date Date to be converted.
	 * @return A new instance of {@link XMLGregorianCalendar}.
	 * @throws DatatypeConfigurationException
	 */
	private XMLGregorianCalendar calendarWithDate(Date date) {
		try {
			GregorianCalendar c = new GregorianCalendar();
    		c.setTime(date);
			return DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
		} catch (DatatypeConfigurationException e) {
			// Unless there is a terrible configuration error, this should not happen 
			e.printStackTrace();
		}
		return null;
    }
	
	/**
	 * Call the initActivation method of the PowerAuth 2.0 Server SOAP interface.
	 * @param request {@link InitActivationRequest} instance
	 * @return {@link InitActivationResponse}
	 */
	public InitActivationResponse initActivation(InitActivationRequest request) {
		return (InitActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	/**
	 * Call the initActivation method of the PowerAuth 2.0 Server SOAP interface.
	 * @param userId User ID for which a new CREATED activation should be created.
	 * @return {@link InitActivationReponse}
	 */
	public InitActivationResponse initActivation(String userId) {
		InitActivationRequest request = new InitActivationRequest();
		request.setUserId(userId);
		return this.initActivation(request);
	}
	
	/**
	 * Call the prepareActivation method of the PowerAuth 2.0 Server SOAP interface.
	 * @param request {@link PrepareActivationRequest} instance
	 * @return {@link PrepareActivationResponse}
	 */
	public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) {
		return (PrepareActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	/**
	 * Call the prepareActivation method of the PowerAuth 2.0 Server SOAP interface.
	 * @param activationIdShort Short activation ID.
	 * @param activationName Name of this activation.
	 * @param activationNonce Activation nonce.
	 * @param cDevicePublicKey Device public key encrypted with activation OTP.
	 * @param extras Additional, application specific information.
	 * @return {@link PrepareActivationResponse}
	 */
	public PrepareActivationResponse prepareActivation(String activationIdShort, String activationName, String activationNonce, String cDevicePublicKey, String extras) {
		PrepareActivationRequest request = new PrepareActivationRequest();
		request.setActivationIdShort(activationIdShort);
		request.setActivationName(activationName);
		request.setActivationNonce(activationNonce);
		request.setCDevicePublicKey(cDevicePublicKey);
		request.setExtras(extras);
		return this.prepareActivation(request);
	}
	
	/**
	 * Call the commitActivation method of the PowerAuth 2.0 Server SOAP interface.
	 * @param request {@link CommitActivationRequest} instance
	 * @return {@link CommitActivationResponse}
	 */
	public CommitActivationResponse commitActivation(CommitActivationRequest request) {
		return (CommitActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	/**
	 * Call the prepareActivation method of the PowerAuth 2.0 Server SOAP interface.
	 * @param activationId Activation ID for activation to be commited.
	 * @return {@link CommitActivationResponse}
	 */
	public CommitActivationResponse commitActivation(String activationId) {
		CommitActivationRequest request = new CommitActivationRequest();
		request.setActivationId(activationId);
		return this.commitActivation(request);
	}
	
	/**
	 * Call the getActivationStatus method of the PowerAuth 2.0 Server SOAP interface.
	 * @param request {@link GetActivationStatusRequest} instance
	 * @return {@link GetActivationStatusResponse}
	 */
	public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) {
		return (GetActivationStatusResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	/**
	 * Call the getActivationStatus method of the PowerAuth 2.0 Server SOAP interface.
	 * @param activationId Activation Id to lookup information for.
	 * @return {@link GetActivationStatusResponse}
	 */
	public GetActivationStatusResponse getActivationStatus(String activationId) {
		GetActivationStatusRequest request = new GetActivationStatusRequest();
		request.setActivationId(activationId);
		return this.getActivationStatus(request);
	}
	
	/**
	 * Call the getActivationListForUser method of the PowerAuth 2.0 Server SOAP interface.
	 * @param request {@link GetActivationListForUserRequest} instance
	 * @return {@link GetActivationListForUserResponse}
	 */
	public GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) {
		return (GetActivationListForUserResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	/**
	 * Call the getActivationListForUser method of the PowerAuth 2.0 Server SOAP interface.
	 * @param userId User ID to fetch the activations for.
	 * @return List of activation instances for given user. 
	 */
	public List<Activations> getActivationListForUser(String userId) {
		GetActivationListForUserRequest request = new GetActivationListForUserRequest();
		request.setUserId(userId);
		return this.getActivationListForUser(request).getActivations();
	}
	
	/**
	 * Call the removeActivation method of the PowerAuth 2.0 Server SOAP interface.
	 * @param request {@link RemoveActivationRequest} instance.
	 * @return {@link RemoveActivationResponse}
	 */
	public RemoveActivationResponse removeActivation(RemoveActivationRequest request) {
		return (RemoveActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	/**
	 * Call the removeActivation method of the PowerAuth 2.0 Server SOAP interface.
	 * @param activationId Activation ID of activation to be removed.
	 * @return {@link RemoveActivationResponse}
	 */
	public RemoveActivationResponse removeActivation(String activationId) {
		RemoveActivationRequest request = new RemoveActivationRequest();
		request.setActivationId(activationId);
		return this.removeActivation(request);
	}
	
	/**
	 * Call the blockActivation method of the PowerAuth 2.0 Server SOAP interface.
	 * @param request {@link BlockActivationRequest} instance.
	 * @return {@link BlockActivationResponse}
	 */
	public BlockActivationResponse blockActivation(BlockActivationRequest request) {
		return (BlockActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	/**
	 * Call the blockActivation method of the PowerAuth 2.0 Server SOAP interface.
	 * @param activationId Activation ID of activation to be blocked.
	 * @return {@link BlockActivationResponse}
	 */
	public BlockActivationResponse blockActivation(String activationId) {
		BlockActivationRequest request = new BlockActivationRequest();
		request.setActivationId(activationId);
		return this.blockActivation(request);
	}
	
	/**
	 * Call the unblockActivation method of the PowerAuth 2.0 Server SOAP interface.
	 * @param request {@link UnblockActivationRequest} instance.
	 * @return {@link UnblockActivationResponse}
	 */
	public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) {
		return (UnblockActivationResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	/**
	 * Call the unblockActivation method of the PowerAuth 2.0 Server SOAP interface.
	 * @param activationId Activation ID of activation to be unblocked.
	 * @return {@link UnblockActivationResponse}
	 */
	public UnblockActivationResponse unblockActivation(String activationId) {
		UnblockActivationRequest request = new UnblockActivationRequest();
		request.setActivationId(activationId);
		return this.unblockActivation(request);
	}
	
	/**
	 * Call the vaultUnlock method of the PowerAuth 2.0 Server SOAP interface.
	 * @param request {@link VaultUnlockRequest} instance
	 * @return {@link VaultUnlockResponse}
	 */
	public VaultUnlockResponse unlockVault(VaultUnlockRequest request) {
		return (VaultUnlockResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	/**
	 * Call the vaultUnlock method of the PowerAuth 2.0 Server SOAP interface.
	 * @param activationId Activation Id of an activation to be used for authentication. 
	 * @param signature Vault opening request signature.
	 * @param signatureType Vault opening request signature type.
	 * @return {@link VaultUnlockResponse}
	 */
	public VaultUnlockResponse unlockVault(String activationId, String signature, String signatureType) {
		VaultUnlockRequest request = new VaultUnlockRequest();
		request.setActivationId(activationId);
		request.setSignature(signature);
		request.setSignatureType(signatureType);
		return this.unlockVault(request);
	}
	
	/**
	 * Call the verifySignature method of the PowerAuth 2.0 Server SOAP interface.
	 * @param request {@link VerifySignatureRequest} instance.
	 * @return {@link VerifySignatureResponse}
	 */
	public VerifySignatureResponse verifySignature(VerifySignatureRequest request) {
		return (VerifySignatureResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	/**
	 * Call the verifySignature method of the PowerAuth 2.0 Server SOAP interface.
	 * @param activationId Activation ID of activation to be used for authentication.
	 * @param data Data to be signed encoded in format as specified by PowerAuth 2.0 data normalization.
	 * @param signature Request signature.
	 * @param signatureType Request signature type.
	 * @return
	 */
	public VerifySignatureResponse verifySignature(String activationId, String data, String signature, String signatureType) {
		VerifySignatureRequest request = new VerifySignatureRequest();
		request.setActivationId(activationId);
		request.setData(data);
		request.setSignature(signature);
		request.setSignatureType(signatureType);
		return this.verifySignature(request);
	}
	
	/**
	 * Call the getSignatureAuditLog method of the PowerAuth 2.0 Server SOAP interface.
	 * @param request {@link SignatureAuditRequest} instance.
	 * @return {@link SignatureAuditResponse}
	 */
	public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) {
		return (SignatureAuditResponse) getWebServiceTemplate().marshalSendAndReceive(request);
	}
	
	/**
	 * Call the verifySignature method of the PowerAuth 2.0 Server SOAP interface.
	 * @param userId User ID to query the audit log against.
	 * @param startingDate Limit the results to given starting date (= "newer than")
	 * @param endingDate Limit the results to given ending date (= "older than")
	 * @return List of signature audit items {@link SignatureAuditResponse.Items}
	 */
	public List<SignatureAuditResponse.Items> getSignatureAuditLog(String userId, Date startingDate, Date endingDate) {
		SignatureAuditRequest request = new SignatureAuditRequest();
		request.setUserId(userId);
		request.setTimestampFrom(calendarWithDate(startingDate));
		request.setTimestampTo(calendarWithDate(endingDate));
		return this.getSignatureAuditLog(request).getItems();
	}

}
