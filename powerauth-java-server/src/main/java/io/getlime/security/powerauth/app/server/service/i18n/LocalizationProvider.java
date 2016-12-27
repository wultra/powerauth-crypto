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

package io.getlime.security.powerauth.app.server.service.i18n;

import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.stereotype.Service;

import java.util.Locale;

@Service
public class LocalizationProvider {

    @Bean
    public ResourceBundleMessageSource messageSource() {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasename("i18n/errors");
        source.setUseCodeAsDefaultMessage(true);
        return source;
    }

    public String getLocalizedErrorMessage(String code) {
        return this.getLocalizedErrorMessage(code, Locale.ENGLISH);
    }

    public String getLocalizedErrorMessage(String code, Locale locale) {
        return messageSource().getMessage("ServiceError." + code, null, locale);
    }

    public GenericServiceException buildExceptionForCode(String code) {
        return this.buildExceptionForCode(code, Locale.ENGLISH);
    }

    public GenericServiceException buildExceptionForCode(String code, Locale locale) {
        String message = this.getLocalizedErrorMessage(code);
        String localizedMessage = this.getLocalizedErrorMessage(code, locale);
        return new GenericServiceException(code, message, localizedMessage);
    }

}
