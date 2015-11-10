package io.getlime.security.service;

import com.google.common.collect.ImmutableSet;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.BlockActivationRequest;
import io.getlime.security.powerauth.BlockActivationResponse;
import io.getlime.security.powerauth.CommitActivationRequest;
import io.getlime.security.powerauth.CommitActivationResponse;
import io.getlime.security.powerauth.GetActivationListForUserRequest;
import io.getlime.security.powerauth.GetActivationListForUserResponse;
import io.getlime.security.powerauth.GetActivationListForUserResponse.Activations;
import io.getlime.security.powerauth.GetActivationStatusRequest;
import io.getlime.security.powerauth.GetActivationStatusResponse;
import io.getlime.security.powerauth.InitActivationRequest;
import io.getlime.security.powerauth.InitActivationResponse;
import io.getlime.security.powerauth.PrepareActivationRequest;
import io.getlime.security.powerauth.PrepareActivationResponse;
import io.getlime.security.powerauth.RemoveActivationRequest;
import io.getlime.security.powerauth.RemoveActivationResponse;
import io.getlime.security.powerauth.UnblockActivationRequest;
import io.getlime.security.powerauth.UnblockActivationResponse;
import io.getlime.security.powerauth.VerifySignatureRequest;
import io.getlime.security.powerauth.VerifySignatureResponse;
import io.getlime.security.powerauth.lib.config.PowerAuthConstants;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.util.KeyConversionUtils;
import io.getlime.security.powerauth.server.activation.PowerAuthServerActivation;
import io.getlime.security.powerauth.server.signature.PowerAuthServerSignature;
import io.getlime.security.repository.MasterKeyPairRepository;
import io.getlime.security.repository.PowerAuthRepository;
import io.getlime.security.repository.model.ActivationRecordEntity;
import io.getlime.security.repository.model.ActivationStatus;
import io.getlime.security.repository.model.MasterKeyPairEntity;
import io.getlime.security.service.util.ModelUtil;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class PowerAuthServiceImpl implements PowerAuthService {

	@Autowired
	private PowerAuthRepository powerAuthRepository;

	@Autowired
	private MasterKeyPairRepository masterKeyPairRepository;

	private final PowerAuthServerActivation powerAuthServerActivation = new PowerAuthServerActivation();
	private final PowerAuthServerSignature powerAuthServerSignature = new PowerAuthServerSignature();
	private final KeyConversionUtils keyConversionUtilities = new KeyConversionUtils();

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Override
	public GetActivationListForUserResponse getActivatioListForUser(GetActivationListForUserRequest request)
			throws Exception {
		String userId = request.getUserId();
		List<ActivationRecordEntity> activationsList = powerAuthRepository.findByUserId(userId);

		GetActivationListForUserResponse response = new GetActivationListForUserResponse();
		response.setUserId(userId);
		if (activationsList != null) {
			for (ActivationRecordEntity activation : activationsList) {
				Activations activationServiceItem = new Activations();
				activationServiceItem.setActivationId(activation.getActivationId());
				activationServiceItem.setActivationStatus(ModelUtil.toServiceStatus(activation.getActivationStatus()));
				activationServiceItem.setClientName(activation.getClientName());
				activationServiceItem.setUserId(activation.getUserId());
				response.getActivations().add(activationServiceItem);
			}
		}
		return response;
	}

	@Override
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws Exception {
        
		String activationId = request.getActivationId();
        ActivationRecordEntity activation = powerAuthRepository.findFirstByActivationId(activationId);
        
        // Handle the case with incorrect activation instance first here
        if (activation == null || activation.getActivationStatus() == ActivationStatus.CREATED) {
        	
        	// Created activations do exist in DB, but should behave as if they didn't
        	GetActivationStatusResponse response = new GetActivationStatusResponse();
        	response.setActivationId(activationId);
        	byte[] randomStatusBlob = new KeyGenerator().generateRandomBytes(16);
        	response.setCStatusBlob(BaseEncoding.base64().encode(randomStatusBlob));
        	return response;
        	
        } else {
        	
        	// Get the server private and device public keys to compute the transport key 
        	PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(activation.getServerPrivateKey());
        	PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(activation.getDevicePublicKey());
        
        	SecretKey masterSecretKey = powerAuthServerSignature.generateServerMasterSecretKey(
        			serverPrivateKey, 
        			devicePublicKey
        	);
        	SecretKey transportKey = powerAuthServerSignature.generateServerTransportKey(masterSecretKey);
        
        	// Encrypt the status blob
        	byte[] C_statusBlob = powerAuthServerActivation.encryptedStatusBlob(
        			activation.getActivationStatus().getByte(),
        			activation.getCounter(),
        			transportKey	
        	);
        
        	// return the data
        	GetActivationStatusResponse response = new GetActivationStatusResponse();
        	response.setActivationId(activationId);
        	response.setCStatusBlob(BaseEncoding.base64().encode(C_statusBlob));
        
        	return response;
        	
        }
        
    }

	@Override
	public InitActivationResponse initActivation(InitActivationRequest request) throws Exception {

		try {

			// Get request parameters
			String userId = request.getUserId();

			// Generate timestamp in advance
			Long timestamp = (System.currentTimeMillis() / 1000L);

			// Fetch the latest master private key
			MasterKeyPairEntity masterKeyPair = masterKeyPairRepository.findFirstByOrderByTimestampCreatedDesc();
			byte[] masterPrivateKeyBytes = BaseEncoding.base64().decode(masterKeyPair.getMasterKeyPrivateBase64());
			PrivateKey masterPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(masterPrivateKeyBytes);

			// Generate new activation data
			String activationId = powerAuthServerActivation.generateActivationId();
			String activationIdShort = powerAuthServerActivation.generateActivationIdShort();
			String activationOtp = powerAuthServerActivation.generateActivationOTP();
			byte[] activationSignature = powerAuthServerActivation.generateActivationSignature(activationIdShort,
					activationOtp, masterPrivateKey);
			String activationSignatureBase64 = BaseEncoding.base64().encode(activationSignature);
			KeyPair serverKeyPair = powerAuthServerActivation.generateServerKeyPair();

			ActivationRecordEntity activation = new ActivationRecordEntity(activationId, activationIdShort,
					activationOtp, userId, null,
					keyConversionUtilities.convertPrivateKeyToBytes(serverKeyPair.getPrivate()),
					keyConversionUtilities.convertPublicKeyToBytes(serverKeyPair.getPublic()), null, new Long(0),
					new Long(0), timestamp, timestamp, ActivationStatus.CREATED, masterKeyPair);

			powerAuthRepository.save(activation);

			InitActivationResponse response = new InitActivationResponse();
			response.setActivationIdShort(activationIdShort);
			response.setUserId(request.getUserId());
			response.setActivationOTP(activationOtp);
			response.setActivationSignature(activationSignatureBase64);

			return response;
			
		} catch (InvalidKeySpecException | InvalidKeyException ex) {
			
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			return null;
			
		}
	}

	@Override
	public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws Exception {
		
		// Get request parameters
		String activationIdShort = request.getActivationIdShort();
		String activationNonceBase64 = request.getActivationNonce();
		String cDevicePublicKeyBase64 = request.getCDevicePublicKey();
		String clientName = request.getClientName();

		// Fetch remaining the current activation by short activation ID
		Set<ActivationStatus> states = ImmutableSet.of(ActivationStatus.CREATED);
		ActivationRecordEntity activation = powerAuthRepository
				.findFirstByActivationIdShortAndActivationStatusIn(activationIdShort, states);

		// Decrypt the device public key
		byte[] C_devicePublicKey = BaseEncoding.base64().decode(cDevicePublicKeyBase64);
		byte[] activationNonce = BaseEncoding.base64().decode(activationNonceBase64);
		PublicKey devicePublicKey = powerAuthServerActivation.decryptDevicePublicKey(C_devicePublicKey,
				activationIdShort, activation.getActivationOTP(), activationNonce);

		// Update and persist the activation record
		activation.setActivationStatus(ActivationStatus.OTP_USED);
		activation.setDevicePublicKey(devicePublicKey.getEncoded());
		activation.setClientName(clientName);
		powerAuthRepository.save(activation);

		// Generate response data
		byte[] activationNonceServer = powerAuthServerActivation.generateActivationNonce();
		PublicKey serverPublicKey = keyConversionUtilities.convertBytesToPublicKey(activation.getServerPublicKey());
		KeyPair ephemeralKeyPair = new KeyGenerator().generateKeyPair();
		PrivateKey ephemeralPrivateKey = ephemeralKeyPair.getPrivate();
		PublicKey ephemeralPublicKey = ephemeralKeyPair.getPublic();
		byte[] ephemeralPublicKeyBytes = keyConversionUtilities.convertPublicKeyToBytes(ephemeralPublicKey);
		byte[] masterPrivateKeyBytes = BaseEncoding.base64()
				.decode(activation.getMasterKeypair().getMasterKeyPrivateBase64());
		PrivateKey masterPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(masterPrivateKeyBytes);
		String activationOtp = activation.getActivationOTP();

		// Encrypt the public key
		byte[] C_serverPublicKey = powerAuthServerActivation.encryptServerPublicKey(serverPublicKey, devicePublicKey,
				ephemeralPrivateKey, activationOtp, activationIdShort, activationNonceServer);

		// Get encrypted public key signature
		byte[] C_serverPubKeySignature = powerAuthServerActivation.computeServerPublicKeySignature(C_serverPublicKey,
				masterPrivateKey);

		// Compute the response
		PrepareActivationResponse response = new PrepareActivationResponse();
		response.setActivationId(activation.getActivationId());
		response.setActivationNonce(BaseEncoding.base64().encode(activationNonceServer));
		response.setCServerPublicKey(BaseEncoding.base64().encode(C_serverPublicKey));
		response.setCServerPublicKeySignature(BaseEncoding.base64().encode(C_serverPubKeySignature));
		response.setEphemeralPublicKey(BaseEncoding.base64().encode(ephemeralPublicKeyBytes));

		return response;
		
	}

	@Override
	public VerifySignatureResponse verifySignature(VerifySignatureRequest request) throws Exception {
		
		// Get request data
		String activationId = request.getActivationId();
		byte[] data = BaseEncoding.base64().decode(request.getData());
		String signature = request.getSignature();
		
		// Fetch related activation
        ActivationRecordEntity activation = powerAuthRepository.findFirstByActivationId(activationId);
        
        // Only validate signature for existing ACTIVE activation records
        if (activation != null && activation.getActivationStatus() == ActivationStatus.ACTIVE) {
        	
        	// Get the server private and device public keys to compute the signing key 
        	PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(activation.getServerPrivateKey());
        	PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(activation.getDevicePublicKey());
        
        	SecretKey masterSecretKey = powerAuthServerSignature.generateServerMasterSecretKey(
        			serverPrivateKey, 
        			devicePublicKey
        	);
        	SecretKey signatureKey = powerAuthServerSignature.generateServerSignatureKey(masterSecretKey);
        	
        	// Verify the signature
        	boolean signatureValid = powerAuthServerSignature.verifySignatureForData(data, signature, signatureKey, activation.getCounter());
        	if (!signatureValid) {
        		
        		// Update failed attempts and block the activation, if necessary
        		activation.setFailedAttempts(activation.getFailedAttempts() + 1);
            	Long remainingAttempts = (PowerAuthConstants.SIGNATURE_MAX_FAILED_ATTEMPTS - activation.getFailedAttempts());
            	if (remainingAttempts <= 0) {
            		activation.setActivationStatus(ActivationStatus.BLOCKED);
            	}
            	powerAuthRepository.save(activation);
            
            	// return the data
            	VerifySignatureResponse response = new VerifySignatureResponse();
            	response.setActivationId(activationId);
            	response.setActivationStatus(ModelUtil.toServiceStatus(activation.getActivationStatus()));
            	response.setRemainingAttempts(BigInteger.valueOf(remainingAttempts));
            	response.setSignatureValid(false);
            	response.setUserId(activation.getUserId());
            	
            	return response;
        		
        	} else {
        		
        		// Reset failed attempt count
        		activation.setFailedAttempts(0L);
        		powerAuthRepository.save(activation);
        		
        		// return the data
            	VerifySignatureResponse response = new VerifySignatureResponse();
            	response.setActivationId(activationId);
            	response.setActivationStatus(ModelUtil.toServiceStatus(ActivationStatus.REMOVED));
            	response.setRemainingAttempts(BigInteger.valueOf(PowerAuthConstants.SIGNATURE_MAX_FAILED_ATTEMPTS));
            	response.setSignatureValid(true);
            	response.setUserId(activation.getUserId());
            	
            	return response;
        	}
        	
        } else {
        	
        	// return the data
        	VerifySignatureResponse response = new VerifySignatureResponse();
        	response.setActivationId(activationId);
        	response.setActivationStatus(ModelUtil.toServiceStatus(ActivationStatus.REMOVED));
        	response.setRemainingAttempts(BigInteger.valueOf(0));
        	response.setSignatureValid(false);
        	response.setUserId("UNKNOWN");
        	
        	return response;
        	
        }
	}

	@Override
	public CommitActivationResponse commitActivation(CommitActivationRequest request) throws Exception {
		String activationId = request.getActivationId();
		ActivationRecordEntity activation = powerAuthRepository.findFirstByActivationId(activationId);
		boolean activated = false;
		if (activation != null) { // does the record even exist?
			activated = true;
			activation.setActivationStatus(ActivationStatus.ACTIVE);
			powerAuthRepository.save(activation);
		}
		CommitActivationResponse response = new CommitActivationResponse();
		response.setActivationId(activationId);
		response.setActivated(activated);
		return response;
	}

	@Override
	public RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws Exception {
		String activationId = request.getActivationId();
		ActivationRecordEntity activation = powerAuthRepository.findFirstByActivationId(activationId);
		boolean removed = false;
		if (activation != null) { // does the record even exist?
			removed = true;
			activation.setActivationStatus(ActivationStatus.REMOVED);
			powerAuthRepository.save(activation);
		}
		RemoveActivationResponse response = new RemoveActivationResponse();
		response.setActivationId(activationId);
		response.setRemoved(removed);
		return response;
	}

	@Override
	public BlockActivationResponse blockActivation(BlockActivationRequest request) throws Exception {
		String activationId = request.getActivationId();
		ActivationRecordEntity activation = powerAuthRepository.findFirstByActivationId(activationId);
		if (activation != null && activation.getActivationStatus().equals(ActivationStatus.ACTIVE)) { // does
																										// the
																										// record
																										// even
																										// exist,
																										// is
																										// it
																										// in
																										// correct
																										// state?
			activation.setActivationStatus(ActivationStatus.BLOCKED);
			powerAuthRepository.save(activation);
		}
		BlockActivationResponse response = new BlockActivationResponse();
		response.setActivationId(activationId);
		response.setActivationStatus(ModelUtil.toServiceStatus(activation.getActivationStatus()));
		return response;
	}

	@Override
	public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws Exception {
		String activationId = request.getActivationId();
		ActivationRecordEntity activation = powerAuthRepository.findFirstByActivationId(activationId);
		if (activation != null && activation.getActivationStatus().equals(ActivationStatus.BLOCKED)) { // does
																										// the
																										// record
																										// even
																										// exist,
																										// is
																										// it
																										// in
																										// correct
																										// state?
			activation.setActivationStatus(ActivationStatus.ACTIVE);
			powerAuthRepository.save(activation);
		}
		UnblockActivationResponse response = new UnblockActivationResponse();
		response.setActivationId(activationId);
		response.setActivationStatus(ModelUtil.toServiceStatus(activation.getActivationStatus()));
		return response;
	}

}
