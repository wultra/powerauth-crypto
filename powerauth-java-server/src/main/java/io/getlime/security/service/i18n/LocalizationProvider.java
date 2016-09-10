package io.getlime.security.service.i18n;

import io.getlime.security.service.exceptions.GenericServiceException;
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
