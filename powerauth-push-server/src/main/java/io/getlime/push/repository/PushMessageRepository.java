package io.getlime.push.repository;

import io.getlime.push.repository.model.PushMessageEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Repository interface used to access push message database.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Repository
public interface PushMessageRepository extends CrudRepository<PushMessageEntity, Long> {

    /**
     * Find all push messages with given status. Used primarily to obtain pending activations (in PENDING status).
     * @param status Push message status.
     * @return List of all messages with given status.
     */
    List<PushMessageEntity> findByStatus(PushMessageEntity.Status status);

}
