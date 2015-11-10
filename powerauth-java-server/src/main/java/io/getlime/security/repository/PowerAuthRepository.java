package io.getlime.security.repository;

import io.getlime.security.repository.model.ActivationRecordEntity;
import io.getlime.security.repository.model.ActivationStatus;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Component;

@Component
public interface PowerAuthRepository extends CrudRepository<ActivationRecordEntity, String> {

    ActivationRecordEntity findFirstByActivationId(String activationId);
    
    List<ActivationRecordEntity> findByUserId(String userId);

    List<ActivationRecordEntity> findByActivationIdShortAndActivationStatusIn(String activationIdShort, Collection<Long> states);

    @Modifying
    @Query("update pa_activation a set a.activationStatus = :activationStatus where a.activationId = :activationId")
    int setActivationStatus(@Param("activationId") String activationId, @Param("activationStatus") ActivationStatus status);
    
    @Modifying
    @Query("update pa_activation a set a.timestampLastUsed = :timestamp where a.activationId = :activationId")
    int setTimestampLastUsed(@Param("activationId") String activationId, @Param("timestamp") Long timestamp);
    
    @Modifying
    @Query("update pa_activation a set a.failedAttempts = a.failedAttempts + 1 where a.activationId = :activationId")
    int incrementFailedAttempts(@Param("activationId") String activationId);
    
    @Modifying
    @Query("update pa_activation a set a.failedAttempts = 0 where a.activationId = :activationId")
    int resetFailedAttempts(@Param("activationId") String activationId);
    
    @Modifying
    @Query("update pa_activation a set a.failedAttempts = :failedAttempts where a.activationId = :activationId")
    int setFailedAttempts(@Param("activationId") String activationId, @Param("failedAttempts") Long failedAttempts);

}
