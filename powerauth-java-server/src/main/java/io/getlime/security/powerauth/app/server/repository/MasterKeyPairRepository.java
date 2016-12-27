/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.app.server.repository;

import io.getlime.security.powerauth.app.server.repository.model.entity.MasterKeyPairEntity;
import org.springframework.data.repository.CrudRepository;

/**
 * Database repository for accessing Master Key Pair data.
 *
 * @author Petr Dvorak
 */
public interface MasterKeyPairRepository extends CrudRepository<MasterKeyPairEntity, Long> {

    /**
     * Find one newest master key pair with a given application ID
     *
     * @param id Application ID
     * @return The newest Master Key Pair for given application.
     */
    MasterKeyPairEntity findFirstByApplicationIdOrderByTimestampCreatedDesc(Long id);

}
