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
import io.getlime.security.powerauth.SignatureAuditRequest;
import io.getlime.security.powerauth.SignatureAuditResponse;
import io.getlime.security.powerauth.UnblockActivationRequest;
import io.getlime.security.powerauth.UnblockActivationResponse;
import io.getlime.security.powerauth.VaultUnlockRequest;
import io.getlime.security.powerauth.VaultUnlockResponse;
import io.getlime.security.powerauth.VerifySignatureRequest;
import io.getlime.security.powerauth.VerifySignatureResponse;
import io.getlime.security.powerauth.lib.config.PowerAuthConstants;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.util.KeyConversionUtils;
import io.getlime.security.powerauth.server.activation.PowerAuthServerActivation;
import io.getlime.security.powerauth.server.keyfactory.PowerAuthServerKeyFactory;
import io.getlime.security.powerauth.server.signature.PowerAuthServerSignature;
import io.getlime.security.powerauth.server.vault.PowerAuthServerVault;
import io.getlime.security.repository.MasterKeyPairRepository;
import io.getlime.security.repository.PowerAuthRepository;
import io.getlime.security.repository.SignatureAuditRepository;
import io.getlime.security.repository.model.ActivationStatus;
import io.getlime.security.repository.model.entity.ActivationRecordEntity;
import io.getlime.security.repository.model.entity.MasterKeyPairEntity;
import io.getlime.security.repository.model.entity.SignatureEntity;
import io.getlime.security.service.exceptions.GenericServiceException;
import io.getlime.security.service.util.ModelUtil;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class PowerAuthServiceImpl implements PowerAuthService {

	@Autowired
	private PowerAuthRepository powerAuthRepository;

	@Autowired
	private MasterKeyPairRepository masterKeyPairRepository;

	@Autowired
	private SignatureAuditRepository signatureAuditRepository;

	private final PowerAuthServerActivation powerAuthServerActivation = new PowerAuthServerActivation();
	private final PowerAuthServerSignature powerAuthServerSignature = new PowerAuthServerSignature();
	private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
	private final PowerAuthServerVault powerAuthServerVault = new PowerAuthServerVault();
	private final KeyConversionUtils keyConversionUtilities = new KeyConversionUtils();

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Override
	public GetActivationListForUserResponse getActivatioListForUser(GetActivationListForUserRequest request) throws Exception {
		try {
			String userId = request.getUserId();

			// Generate timestamp in advance
			Date timestamp = new Date();

			List<ActivationRecordEntity> activationsList = powerAuthRepository.findByUserId(userId);

			GetActivationListForUserResponse response = new GetActivationListForUserResponse();
			response.setUserId(userId);
			if (activationsList != null) {
				for (ActivationRecordEntity activation : activationsList) {

					// Deactivate old pending activations first
					if ((activation.getActivationStatus().equals(ActivationStatus.CREATED) || activation.getActivationStatus().equals(ActivationStatus.OTP_USED)) && timestamp.getTime() - activation.getTimestampCreated().getTime() > PowerAuthConstants.ACTIVATION_VALIDITY_BEFORE_ACTIVE) {
						activation.setActivationStatus(ActivationStatus.REMOVED);
						powerAuthRepository.save(activation);
					}

					// Map between repository object and service objects
					Activations activationServiceItem = new Activations();
					activationServiceItem.setActivationId(activation.getActivationId());
					activationServiceItem.setActivationStatus(ModelUtil.toServiceStatus(activation.getActivationStatus()));
					activationServiceItem.setActivationName(activation.getActivationName());
					activationServiceItem.setExtras(activation.getExtras());
					activationServiceItem.setTimestampCreated(ModelUtil.calendarWithDate(activation.getTimestampCreated()));
					activationServiceItem.setTimestampLastUsed(ModelUtil.calendarWithDate(activation.getTimestampLastUsed()));
					activationServiceItem.setUserId(activation.getUserId());
					response.getActivations().add(activationServiceItem);
				}
			}
			return response;
		} catch (Exception ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw new GenericServiceException("Unknown exception has occurred");
		}
	}

	@Override
	public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws Exception {
		try {
			String activationId = request.getActivationId();

			// Generate timestamp in advance
			Date timestamp = new Date();

			ActivationRecordEntity activation = powerAuthRepository.findFirstByActivationId(activationId);

			// Handle the case with incorrect activation instance first here
			if (activation == null || activation.getActivationStatus() == ActivationStatus.CREATED) {

				// Created activations do exist in DB, but should behave as if
				// they didn't
				GetActivationStatusResponse response = new GetActivationStatusResponse();
				response.setActivationId(activationId);
				response.setActivationStatus(ModelUtil.toServiceStatus(ActivationStatus.CREATED));
				byte[] randomStatusBlob = new KeyGenerator().generateRandomBytes(16);
				response.setCStatusBlob(BaseEncoding.base64().encode(randomStatusBlob));
				return response;

			} else {

				// Deactivate old pending activations first
				if ((activation.getActivationStatus().equals(ActivationStatus.CREATED) || activation.getActivationStatus().equals(ActivationStatus.OTP_USED)) && timestamp.getTime() - activation.getTimestampCreated().getTime() > PowerAuthConstants.ACTIVATION_VALIDITY_BEFORE_ACTIVE) {
					activation.setActivationStatus(ActivationStatus.REMOVED);
					powerAuthRepository.save(activation);
				}

				// Get the server private and device public keys to compute the
				// transport key
				String serverPrivateKeyBase64 = activation.getServerPrivateKeyBase64();
				String devicePublicKeyBase64 = activation.getDevicePublicKeyBase64();
				PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(BaseEncoding.base64().decode(serverPrivateKeyBase64));
				PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(BaseEncoding.base64().decode(devicePublicKeyBase64));

				SecretKey masterSecretKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
				SecretKey transportKey = powerAuthServerKeyFactory.generateServerTransportKey(masterSecretKey);

				// Encrypt the status blob
				byte[] C_statusBlob = powerAuthServerActivation.encryptedStatusBlob(activation.getActivationStatus().getByte(), activation.getCounter(), activation.getFailedAttempts().byteValue(), transportKey);

				// return the data
				GetActivationStatusResponse response = new GetActivationStatusResponse();
				response.setActivationId(activationId);
				response.setActivationStatus(ModelUtil.toServiceStatus(activation.getActivationStatus()));
				response.setActivationName(activation.getActivationName());
				response.setExtras(activation.getExtras());
				response.setTimestampCreated(ModelUtil.calendarWithDate(activation.getTimestampCreated()));
				response.setTimestampLastUsed(ModelUtil.calendarWithDate(activation.getTimestampLastUsed()));
				response.setCStatusBlob(BaseEncoding.base64().encode(C_statusBlob));

				return response;

			}
		} catch (Exception ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw new GenericServiceException("Unknown exception has occurred");
		}

	}

	@Override
	@Transactional
	public InitActivationResponse initActivation(InitActivationRequest request) throws Exception {

		try {

			// Get request parameters
			String userId = request.getUserId();

			// Generate timestamp in advance
			Date timestamp = new Date();

			// Fetch the latest master private key
			MasterKeyPairEntity masterKeyPair = masterKeyPairRepository.findFirstByOrderByTimestampCreatedDesc();
			if (masterKeyPair == null) {
				GenericServiceException ex = new GenericServiceException("No master server key pair configured in database");
				Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
				throw ex;
			}
			byte[] masterPrivateKeyBytes = BaseEncoding.base64().decode(masterKeyPair.getMasterKeyPrivateBase64());
			PrivateKey masterPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(masterPrivateKeyBytes);
			if (masterPrivateKey == null) {
				GenericServiceException ex = new GenericServiceException("Master server key pair contains private key in incorrect format");
				Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
				throw ex;
			}

			// Generate new activation data, generate a unique activation ID
			String activationId = null;
			for (int i = 0; i < PowerAuthConstants.ACTIVATION_GENERATE_ACTIVATION_ID_ITERATIONS; i++) {
				String tmpActivationId = powerAuthServerActivation.generateActivationId();
				ActivationRecordEntity record = powerAuthRepository.findFirstByActivationId(tmpActivationId);
				// this activation ID has a collision, reset it and find another
				// one
				if (record == null || (timestamp.getTime() - record.getTimestampCreated().getTime()) > PowerAuthConstants.ACTIVATION_VALIDITY_BEFORE_ACTIVE) {
					activationId = tmpActivationId;
					break;
				}
			}
			if (activationId == null) {
				throw new GenericServiceException("ERROR_GENERIC_ACTIVATION_ID", "Too many failed attempts to generate activation ID.");
			}

			// Generate a unique short activation ID for created and OTP used
			// states
			String activationIdShort = null;
			Set<ActivationStatus> states = ImmutableSet.of(ActivationStatus.CREATED, ActivationStatus.OTP_USED);
			for (int i = 0; i < PowerAuthConstants.ACTIVATION_GENERATE_ACTIVATION_SHORT_ID_ITERATIONS; i++) {
				String tmpActivationIdShort = powerAuthServerActivation.generateActivationIdShort();
				ActivationRecordEntity record = powerAuthRepository.findFirstByActivationIdShortAndActivationStatusInAndTimestampCreatedAfter(tmpActivationIdShort, states, new Date(timestamp.getTime() - PowerAuthConstants.ACTIVATION_VALIDITY_BEFORE_ACTIVE));
				// this activation short ID has a collision, reset it and find
				// another one
				if (record == null) {
					activationIdShort = tmpActivationIdShort;
					break;
				}
			}
			if (activationIdShort == null) {
				throw new GenericServiceException("ERROR_GENERIC_ACTIVATION_ID_SHORT", "Too many failed attempts to generate short activation ID.");
			}

			// Generate activation OTP
			String activationOtp = powerAuthServerActivation.generateActivationOTP();

			// Compute activation signature
			byte[] activationSignature = powerAuthServerActivation.generateActivationSignature(activationIdShort, activationOtp, masterPrivateKey);
			String activationSignatureBase64 = BaseEncoding.base64().encode(activationSignature);

			// Generate server key pair
			KeyPair serverKeyPair = powerAuthServerActivation.generateServerKeyPair();
			byte[] serverKeyPrivateBytes = keyConversionUtilities.convertPrivateKeyToBytes(serverKeyPair.getPrivate());
			byte[] serverKeyPublicBytes = keyConversionUtilities.convertPublicKeyToBytes(serverKeyPair.getPublic());

			// Store the new activation
			ActivationRecordEntity activation = new ActivationRecordEntity(activationId, activationIdShort, activationOtp, userId, null, null, BaseEncoding.base64().encode(serverKeyPrivateBytes), BaseEncoding.base64().encode(serverKeyPublicBytes), null, new Long(0), new Long(0), timestamp, timestamp, ActivationStatus.CREATED, masterKeyPair);

			powerAuthRepository.save(activation);

			// Return the server response
			InitActivationResponse response = new InitActivationResponse();
			response.setActivationId(activationId);
			response.setActivationIdShort(activationIdShort);
			response.setUserId(request.getUserId());
			response.setActivationOTP(activationOtp);
			response.setActivationSignature(activationSignatureBase64);

			return response;

		} catch (GenericServiceException ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw ex;
		} catch (InvalidKeySpecException | InvalidKeyException ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw new GenericServiceException("Key with invalid format was provided");
		}
	}

	@Override
	@Transactional
	public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws Exception {
		try {
			// Get request parameters
			String activationIdShort = request.getActivationIdShort();
			String activationNonceBase64 = request.getActivationNonce();
			String cDevicePublicKeyBase64 = request.getCDevicePublicKey();
			String activationName = request.getActivationName();
			String extras = request.getExtras();

			// Get current timestamp
			Date timestamp = new Date();

			// Fetch the current activation by short activation ID
			Set<ActivationStatus> states = ImmutableSet.of(ActivationStatus.CREATED);
			ActivationRecordEntity activation = powerAuthRepository.findFirstByActivationIdShortAndActivationStatusInAndTimestampCreatedAfter(activationIdShort, states, new Date(timestamp.getTime() - PowerAuthConstants.ACTIVATION_VALIDITY_BEFORE_ACTIVE));

			if (activation == null) {
				throw new GenericServiceException("ERROR_ACTIVATION_EXPIRED", "This activation is already expired.");
			}

			// Decrypt the device public key
			byte[] C_devicePublicKey = BaseEncoding.base64().decode(cDevicePublicKeyBase64);
			byte[] activationNonce = BaseEncoding.base64().decode(activationNonceBase64);
			PublicKey devicePublicKey = powerAuthServerActivation.decryptDevicePublicKey(C_devicePublicKey, activationIdShort, activation.getActivationOTP(), activationNonce);

			// Update and persist the activation record
			activation.setActivationStatus(ActivationStatus.OTP_USED);
			activation.setDevicePublicKeyBase64(BaseEncoding.base64().encode(keyConversionUtilities.convertPublicKeyToBytes(devicePublicKey)));
			activation.setActivationName(activationName);
			activation.setExtras(extras);
			powerAuthRepository.save(activation);

			// Generate response data
			byte[] activationNonceServer = powerAuthServerActivation.generateActivationNonce();
			String serverPublicKeyBase64 = activation.getServerPublicKeyBase64();
			PublicKey serverPublicKey = keyConversionUtilities.convertBytesToPublicKey(BaseEncoding.base64().decode(serverPublicKeyBase64));
			KeyPair ephemeralKeyPair = new KeyGenerator().generateKeyPair();
			PrivateKey ephemeralPrivateKey = ephemeralKeyPair.getPrivate();
			PublicKey ephemeralPublicKey = ephemeralKeyPair.getPublic();
			byte[] ephemeralPublicKeyBytes = keyConversionUtilities.convertPublicKeyToBytes(ephemeralPublicKey);
			String masterPrivateKeyBase64 = activation.getMasterKeypair().getMasterKeyPrivateBase64();
			byte[] masterPrivateKeyBytes = BaseEncoding.base64().decode(masterPrivateKeyBase64);
			PrivateKey masterPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(masterPrivateKeyBytes);
			String activationOtp = activation.getActivationOTP();

			// Encrypt the public key
			byte[] C_serverPublicKey = powerAuthServerActivation.encryptServerPublicKey(serverPublicKey, devicePublicKey, ephemeralPrivateKey, activationOtp, activationIdShort, activationNonceServer);

			// Get encrypted public key signature
			byte[] C_serverPubKeySignature = powerAuthServerActivation.computeServerPublicKeySignature(C_serverPublicKey, masterPrivateKey);

			// Compute the response
			PrepareActivationResponse response = new PrepareActivationResponse();
			response.setActivationId(activation.getActivationId());
			response.setActivationNonce(BaseEncoding.base64().encode(activationNonceServer));
			response.setCServerPublicKey(BaseEncoding.base64().encode(C_serverPublicKey));
			response.setCServerPublicKeySignature(BaseEncoding.base64().encode(C_serverPubKeySignature));
			response.setEphemeralPublicKey(BaseEncoding.base64().encode(ephemeralPublicKeyBytes));

			return response;

		} catch (GenericServiceException ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw ex;
		} catch (Exception ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw new GenericServiceException("Unknown exception has occurred");
		}
	}

	private VerifySignatureResponse verifySignatureImplNonTransaction(VerifySignatureRequest request) throws Exception {
		// Get request data
		String activationId = request.getActivationId();
		byte[] data = request.getData().getBytes("UTF-8");
		String signature = request.getSignature();
		String signatureType = request.getSignatureType().toLowerCase();
		
		// Prepare current timestamp in advance
		Date currentTimestamp = new Date();

		// Fetch related activation
		ActivationRecordEntity activation = powerAuthRepository.findFirstByActivationId(activationId);

		// Only validate signature for existing ACTIVE activation records
		if (activation != null) {
			if (activation.getActivationStatus() == ActivationStatus.ACTIVE) {

				// Get the server private and device public keys
				byte[] serverPrivateKeyBytes = BaseEncoding.base64().decode(activation.getServerPrivateKeyBase64());
				byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(activation.getDevicePublicKeyBase64());
				PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(serverPrivateKeyBytes);
				PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(devicePublicKeyBytes);

				// Compute the master secret key
				SecretKey masterSecretKey = powerAuthServerKeyFactory.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);

				// Get the signature keys according to the signature type
				List<SecretKey> signatureKeys = powerAuthServerKeyFactory.keysForSignatureType(signatureType, masterSecretKey);

				// Verify the signature with given lookahead
				boolean signatureValid = false;
				long ctr = activation.getCounter();
				long lowestValidCounter = ctr;
				for (long iterCtr = ctr; iterCtr < ctr + PowerAuthConstants.SIGNATURE_VALIDATION_LOOKAHEAD; iterCtr++) {
					signatureValid = powerAuthServerSignature.verifySignatureForData(data, signature, signatureKeys, iterCtr);
					if (signatureValid) {
						// set the lowest valid counter and break at the lowest
						// counter where signature validates
						lowestValidCounter = iterCtr;
						break;
					}
				}
				if (signatureValid) {

					// Set the activation record counter to the lowest counter
					// (+1, since the client has incremented the counter)
					activation.setCounter(lowestValidCounter + 1);

					// Reset failed attempt count
					activation.setFailedAttempts(0L);
					
					// Update the last used date
					activation.setTimestampLastUsed(currentTimestamp);
					
					// Save the activation
					powerAuthRepository.save(activation);

					// Audit the signature
					SignatureEntity signatureAuditRecord = new SignatureEntity();
					signatureAuditRecord.setActivation(activation);
					signatureAuditRecord.setActivationCounter(activation.getCounter());
					signatureAuditRecord.setDataBase64(BaseEncoding.base64().encode(data));
					signatureAuditRecord.setSignature(signature);
					signatureAuditRecord.setSignatureType(signatureType);
					signatureAuditRecord.setTimestampCreated(currentTimestamp);
					signatureAuditRepository.save(signatureAuditRecord);

					// return the data
					VerifySignatureResponse response = new VerifySignatureResponse();
					response.setActivationId(activationId);
					response.setActivationStatus(ModelUtil.toServiceStatus(ActivationStatus.ACTIVE));
					response.setRemainingAttempts(BigInteger.valueOf(PowerAuthConstants.SIGNATURE_MAX_FAILED_ATTEMPTS));
					response.setSignatureValid(true);
					response.setUserId(activation.getUserId());

					return response;

				} else {

					// Increment the activation record counter
					activation.setCounter(activation.getCounter() + 1);

					// Update failed attempts and block the activation, if
					// necessary
					activation.setFailedAttempts(activation.getFailedAttempts() + 1);
					Long remainingAttempts = (PowerAuthConstants.SIGNATURE_MAX_FAILED_ATTEMPTS - activation.getFailedAttempts());
					if (remainingAttempts <= 0) {
						activation.setActivationStatus(ActivationStatus.BLOCKED);
					}
					
					// Update the last used date
					activation.setTimestampLastUsed(currentTimestamp);
					
					// Save the activation
					powerAuthRepository.save(activation);

					// return the data
					VerifySignatureResponse response = new VerifySignatureResponse();
					response.setActivationId(activationId);
					response.setActivationStatus(ModelUtil.toServiceStatus(activation.getActivationStatus()));
					response.setRemainingAttempts(BigInteger.valueOf(remainingAttempts));
					response.setSignatureValid(false);
					response.setUserId(activation.getUserId());

					return response;

				}

			} else {

				// Despite the fact activation is not in active state, increase
				// the counter
				activation.setCounter(activation.getCounter() + 1);
				
				// Update the last used date
				activation.setTimestampLastUsed(currentTimestamp);
				
				// Save the activation
				powerAuthRepository.save(activation);

				// return the data
				VerifySignatureResponse response = new VerifySignatureResponse();
				response.setActivationId(activationId);
				response.setActivationStatus(ModelUtil.toServiceStatus(ActivationStatus.REMOVED));
				response.setRemainingAttempts(BigInteger.valueOf(0));
				response.setSignatureValid(false);
				response.setUserId("UNKNOWN");

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
	@Transactional
	public VerifySignatureResponse verifySignature(VerifySignatureRequest request) throws Exception {
		try {
			return this.verifySignatureImplNonTransaction(request);
		} catch (Exception ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw new GenericServiceException("Unknown exception has occurred");
		}
	}

	@Override
	@Transactional
	public CommitActivationResponse commitActivation(CommitActivationRequest request) throws Exception {
		try {
			String activationId = request.getActivationId();
			ActivationRecordEntity activation = powerAuthRepository.findFirstByActivationId(activationId);
			// Get current timestamp
			Date timestamp = new Date();
			if (activation == null || (timestamp.getTime() - activation.getTimestampCreated().getTime()) > PowerAuthConstants.ACTIVATION_VALIDITY_BEFORE_ACTIVE) {
				activation.setActivationStatus(ActivationStatus.REMOVED);
				powerAuthRepository.save(activation);
				throw new GenericServiceException("ERROR_ACTIVATION_EXPIRED", "This activation is already expired.");
			}
			boolean activated = false;
			if (activation != null) { // does the record even exist?
				if (activation.getActivationStatus().equals(ActivationStatus.OTP_USED)) {
					activated = true;
					activation.setActivationStatus(ActivationStatus.ACTIVE);
					powerAuthRepository.save(activation);
				} else {
					throw new GenericServiceException("ERROR_ACTIVATION_COMMIT_STATE", "Only activations in OTP_USED state can be commited");
				}
			}
			CommitActivationResponse response = new CommitActivationResponse();
			response.setActivationId(activationId);
			response.setActivated(activated);
			return response;
		} catch (GenericServiceException ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw ex;
		} catch (Exception ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw new GenericServiceException("Unknown exception has occurred");
		}
	}

	@Override
	@Transactional
	public RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws Exception {
		try {
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
		} catch (Exception ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw new GenericServiceException("Unknown exception has occurred");
		}
	}

	@Override
	@Transactional
	public BlockActivationResponse blockActivation(BlockActivationRequest request) throws Exception {
		try {
			String activationId = request.getActivationId();
			ActivationRecordEntity activation = powerAuthRepository.findFirstByActivationId(activationId);
			if (activation == null) {
				throw new GenericServiceException("Activation with given activation ID was not found");
			}

			// does the record even exist, is it in correct state?
			if (activation != null && activation.getActivationStatus().equals(ActivationStatus.ACTIVE)) {
				activation.setActivationStatus(ActivationStatus.BLOCKED);
				powerAuthRepository.save(activation);
			}
			BlockActivationResponse response = new BlockActivationResponse();
			response.setActivationId(activationId);
			response.setActivationStatus(ModelUtil.toServiceStatus(activation.getActivationStatus()));
			return response;
		} catch (GenericServiceException ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw ex;
		} catch (Exception ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw new GenericServiceException("Unknown exception has occurred");
		}
	}

	@Override
	@Transactional
	public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws Exception {
		try {
			String activationId = request.getActivationId();
			ActivationRecordEntity activation = powerAuthRepository.findFirstByActivationId(activationId);
			if (activation == null) {
				throw new GenericServiceException("Activation with given activation ID was not found");
			}
			// does the record even exist, is it in correct state?
			if (activation != null && activation.getActivationStatus().equals(ActivationStatus.BLOCKED)) {
				activation.setActivationStatus(ActivationStatus.ACTIVE);
				activation.setFailedAttempts(0L);
				powerAuthRepository.save(activation);
			}
			UnblockActivationResponse response = new UnblockActivationResponse();
			response.setActivationId(activationId);
			response.setActivationStatus(ModelUtil.toServiceStatus(activation.getActivationStatus()));
			return response;
		} catch (GenericServiceException ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw ex;
		} catch (Exception ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw new GenericServiceException("Unknown exception has occurred");
		}

	}

	@Override
	@Transactional
	public VaultUnlockResponse vaultUnlock(VaultUnlockRequest request) throws Exception {
		try {

			// Get request data
			String activationId = request.getActivationId();
			String signature = request.getSignature();
			String signatureType = request.getSignatureType().toLowerCase();

			// Verify the signature
			VerifySignatureRequest verifySignatureRequest = new VerifySignatureRequest();
			verifySignatureRequest.setActivationId(activationId);
			verifySignatureRequest.setData(null); // set null data
			verifySignatureRequest.setSignature(signature);
			verifySignatureRequest.setSignatureType(signatureType);
			VerifySignatureResponse verifySignatureResponse = this.verifySignatureImplNonTransaction(verifySignatureRequest);

			// Find related activation record
			ActivationRecordEntity activation = powerAuthRepository.findFirstByActivationId(activationId);

			if (activation != null && activation.getActivationStatus() == ActivationStatus.ACTIVE) {

				// Check if the signature is valid
				if (verifySignatureResponse.isSignatureValid()) {

					// Get the server private and device public keys
					byte[] serverPrivateKeyBytes = BaseEncoding.base64().decode(activation.getServerPrivateKeyBase64());
					byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(activation.getDevicePublicKeyBase64());
					PrivateKey serverPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(serverPrivateKeyBytes);
					PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(devicePublicKeyBytes);

					// Get encrypted vault unlock key and increment the counter
					Long counter = activation.getCounter();
					byte[] cKeyBytes = powerAuthServerVault.encryptVaultEncryptionKey(serverPrivateKey, devicePublicKey, counter);
					activation.setCounter(counter + 1);
					powerAuthRepository.save(activation);

					// return the data
					VaultUnlockResponse response = new VaultUnlockResponse();
					response.setActivationId(activationId);
					response.setActivationStatus(ModelUtil.toServiceStatus(ActivationStatus.ACTIVE));
					response.setRemainingAttempts(BigInteger.valueOf(PowerAuthConstants.SIGNATURE_MAX_FAILED_ATTEMPTS));
					response.setSignatureValid(true);
					response.setUserId(activation.getUserId());
					response.setCVaultEncryptionKey(BaseEncoding.base64().encode(cKeyBytes));

					return response;

				} else {

					// Even if the signature is not valid, increment the counter
					Long counter = activation.getCounter();
					activation.setCounter(counter + 1);
					powerAuthRepository.save(activation);

					// return the data
					VaultUnlockResponse response = new VaultUnlockResponse();
					response.setActivationId(activationId);
					response.setActivationStatus(ModelUtil.toServiceStatus(activation.getActivationStatus()));
					response.setRemainingAttempts(BigInteger.valueOf((PowerAuthConstants.SIGNATURE_MAX_FAILED_ATTEMPTS - activation.getFailedAttempts())));
					response.setSignatureValid(false);
					response.setUserId(activation.getUserId());
					response.setCVaultEncryptionKey(null);

					return response;
				}

			} else {

				// return the data
				VaultUnlockResponse response = new VaultUnlockResponse();
				response.setActivationId(activationId);
				response.setActivationStatus(ModelUtil.toServiceStatus(ActivationStatus.REMOVED));
				response.setRemainingAttempts(BigInteger.valueOf(0));
				response.setSignatureValid(false);
				response.setUserId("UNKNOWN");
				response.setCVaultEncryptionKey(null);

				return response;
			}

		} catch (Exception ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw new GenericServiceException("Unknown exception has occurred");
		}
	}

	@Override
	public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) throws Exception {
		try {

			String userId = request.getUserId();
			Date startingDate = ModelUtil.dateWithCalendar(request.getTimestampFrom());
			Date endingDate = ModelUtil.dateWithCalendar(request.getTimestampTo());

			List<SignatureEntity> signatureAuditEntityList = signatureAuditRepository.findByActivation_UserIdAndTimestampCreatedBetween(userId, startingDate, endingDate);

			SignatureAuditResponse response = new SignatureAuditResponse();
			if (signatureAuditEntityList != null) {
				for (SignatureEntity signatureEntity : signatureAuditEntityList) {

					SignatureAuditResponse.Items item = new SignatureAuditResponse.Items();
					item.setActivationCounter(signatureEntity.getActivationCounter());
					item.setActivationId(signatureEntity.getActivation().getActivationId());
					item.setDataBase64(signatureEntity.getDataBase64());
					item.setId(signatureEntity.getId());
					item.setSignature(signatureEntity.getSignature());
					item.setSignatureType(signatureEntity.getSignatureType());
					item.setTimestampCreated(ModelUtil.calendarWithDate(signatureEntity.getTimestampCreated()));
					item.setUserId(signatureEntity.getActivation().getUserId());

					response.getItems().add(item);
				}
			}

			return response;

		} catch (Exception ex) {
			Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
			throw new GenericServiceException("Unknown exception has occurred");
		}

	}

}
