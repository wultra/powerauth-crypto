package io.getlime.security.repository;

import io.getlime.security.repository.model.ActivationRecordEntity;
import io.getlime.security.repository.model.ActivationStatus;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Component;

@Component
public interface PowerAuthRepository extends CrudRepository<ActivationRecordEntity, String> {

    ActivationRecordEntity findFirstByActivationId(String activationId);

    List<ActivationRecordEntity> findByUserId(String userId);

    ActivationRecordEntity findFirstByActivationIdShortAndActivationStatusInAndTimestampCreatedAfter(String activationIdShort, Collection<ActivationStatus> states, Date timestampCreated);

}
