package io.getlime.security.powerauth.http.validator;

import io.getlime.security.powerauth.http.PowerAuthHttpHeader;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PowerAuthHttpHeaderValidator {

    public static void validate(PowerAuthHttpHeader header) throws InvalidPowerAuthHttpHeaderException {

        // Check if the parsing was successful
        if (header == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_SIGNATURE_INVALID_EMPTY");
        }

        // Check activation ID
        String activationId = header.getActivationId();
        if (activationId == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_ACTIVATION_ID_EMPTY");
        }

        // Check nonce
        String nonce = header.getNonce();
        if (nonce == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_NONCE_EMPTY");
        }

        // Check signature type
        String signatureType = header.getSignatureType();
        if (signatureType == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_SIGNATURE_TYPE_EMPTY");
        }

        // Check signature
        String signature = header.getSignature();
        if (signature == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_SIGNATURE_EMPTY");
        }

        // Check application key.
        String applicationKey = header.getApplicationKey();
        if (applicationKey == null) {
            throw new InvalidPowerAuthHttpHeaderException("POWER_AUTH_APPLICATION_EMPTY");
        }

    }

}