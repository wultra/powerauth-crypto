package io.getlime.security.repository.model;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import org.springframework.stereotype.Component;

@Converter
@Component
public class ActivationStatusConverter implements AttributeConverter<ActivationStatus, Integer> {

	@Override
	public Integer convertToDatabaseColumn(ActivationStatus status) {
		return new Integer(status.getByte());
	}

	@Override
	public ActivationStatus convertToEntityAttribute(Integer b) {
		switch (b) {
		case 1:
			return ActivationStatus.CREATED;
		case 2:
			return ActivationStatus.OTP_USED;
		case 3:
			return ActivationStatus.ACTIVE;
		case 4:
			return ActivationStatus.BLOCKED;
		default:
			return ActivationStatus.REMOVED;
		}
	}

}
