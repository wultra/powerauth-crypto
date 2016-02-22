package io.getlime.security.service.behavior;

import java.util.Date;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.io.BaseEncoding;

import io.getlime.security.powerauth.SignatureAuditResponse;
import io.getlime.security.repository.SignatureAuditRepository;
import io.getlime.security.repository.model.entity.ActivationRecordEntity;
import io.getlime.security.repository.model.entity.SignatureEntity;
import io.getlime.security.service.util.ModelUtil;

@Component
public class AuditingServiceBehavior {

	@Autowired
	private SignatureAuditRepository signatureAuditRepository;
	
	public SignatureAuditResponse getSignatureAuditLog(String userId, Long applicationId, Date startingDate, Date endingDate) throws DatatypeConfigurationException {
		
		List<SignatureEntity> signatureAuditEntityList = null;
		if (applicationId == null) {
			signatureAuditEntityList = signatureAuditRepository.findByActivation_UserIdAndTimestampCreatedBetween(userId, startingDate, endingDate);
		} else {
			signatureAuditEntityList = signatureAuditRepository.findByActivation_ApplicationIdAndActivation_UserIdAndTimestampCreatedBetween(applicationId, userId, startingDate, endingDate);
		}

		SignatureAuditResponse response = new SignatureAuditResponse();
		if (signatureAuditEntityList != null) {
			for (SignatureEntity signatureEntity : signatureAuditEntityList) {

				SignatureAuditResponse.Items item = new SignatureAuditResponse.Items();

				item.setId(signatureEntity.getId());
				item.setActivationCounter(signatureEntity.getActivationCounter());
				item.setActivationStatus(ModelUtil.toServiceStatus(signatureEntity.getActivationStatus()));
				item.setActivationId(signatureEntity.getActivation().getActivationId());
				item.setDataBase64(signatureEntity.getDataBase64());
				item.setSignature(signatureEntity.getSignature());
				item.setSignatureType(signatureEntity.getSignatureType());
				item.setValid(signatureEntity.getValid());
				item.setTimestampCreated(ModelUtil.calendarWithDate(signatureEntity.getTimestampCreated()));
				item.setNote(signatureEntity.getNote());
				item.setUserId(signatureEntity.getActivation().getUserId());

				response.getItems().add(item);
			}
		}

		return response;
	}
	
	public void logSignatureAuditRecord(ActivationRecordEntity activation, String signatureType, String signature, byte[] data, Boolean valid, String note, Date currentTimestamp) {
		// Audit the signature
		SignatureEntity signatureAuditRecord = new SignatureEntity();
		signatureAuditRecord.setActivation(activation);
		signatureAuditRecord.setActivationCounter(activation.getCounter());
		signatureAuditRecord.setActivationStatus(activation.getActivationStatus());
		signatureAuditRecord.setDataBase64(BaseEncoding.base64().encode(data));
		signatureAuditRecord.setSignature(signature);
		signatureAuditRecord.setSignatureType(signatureType);
		signatureAuditRecord.setValid(valid);
		signatureAuditRecord.setNote(note);
		signatureAuditRecord.setTimestampCreated(currentTimestamp);
		signatureAuditRepository.save(signatureAuditRecord);
	}
	
}
