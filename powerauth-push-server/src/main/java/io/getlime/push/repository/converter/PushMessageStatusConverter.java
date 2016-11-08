package io.getlime.push.repository.converter;

import io.getlime.push.repository.model.PushMessageEntity;
import org.springframework.stereotype.Component;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

/**
 * Created by petrdvorak on 02/11/2016.
 */
@Component
@Converter
public class PushMessageStatusConverter implements AttributeConverter<PushMessageEntity.Status, Integer> {

    @Override
    public Integer convertToDatabaseColumn(PushMessageEntity.Status status) {
        return status.getStatus();
    }

    @Override
    public PushMessageEntity.Status convertToEntityAttribute(Integer integer) {
        switch (integer) {
            case 0:
                return PushMessageEntity.Status.PENDING;
            case 1:
                return PushMessageEntity.Status.SENT;
            default:
                return PushMessageEntity.Status.FAILED;
        }
    }
}
