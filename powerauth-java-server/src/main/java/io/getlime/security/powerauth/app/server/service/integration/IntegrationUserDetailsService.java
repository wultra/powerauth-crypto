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
package io.getlime.security.powerauth.app.server.service.integration;

import io.getlime.security.powerauth.app.server.repository.IntegrationRepository;
import io.getlime.security.powerauth.app.server.repository.model.entity.IntegrationEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Class that implements user detail service used for authentication of integrations.
 * Integration is essentially an application that is allowed to communicate with
 * PowerAuth 2.0 Server.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Service
public class IntegrationUserDetailsService implements UserDetailsService {

    private IntegrationRepository integrationRepository;

    /**
     * Constructor to autowire {@link IntegrationRepository} instance.
     * @param integrationRepository Autowired repository.
     */
    @Autowired
    public IntegrationUserDetailsService(IntegrationRepository integrationRepository) {
        this.integrationRepository = integrationRepository;
    }

    /**
     * Method to load user details from the database table "pa_integration" according to "clientToken".
     * @param username Username, represented by Client Token value in the "pa_integration" table.
     * @return User details - an instance of new User object.
     * @throws UsernameNotFoundException When integration with given Client Token was not found.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        IntegrationEntity integration = integrationRepository.findFirstByClientToken(username);
        if (integration != null) {
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            return new User(integration.getClientToken(), integration.getClientSecret(), authorities);
        } else {
            throw new UsernameNotFoundException("No integration found for client token: " + username);
        }
    }

}
