# Dynamic Factor Keys

Dynamic Factor Keys ensure that changes to authentication factors—such as passwords or biometric enrollment—are always reflected in freshly derived cryptographic material shared between the client and server.

Instead of relying on purely local updates, any modification of a factor (for example, changing a password or enabling/disabling biometrics) is accompanied by a server-assisted key exchange. This process results in new factor keys on both sides, effectively binding the updated factor state to newly established secrets.

This design provides two important properties:
- Password changes produce new knowledge factor keys. Each password update triggers a shared-secret exchange with the server, yielding a new knowledge factor key.
- Biometric state is synchronized with the server. Enabling or removing biometrics also derives fresh biometric factor keys and updates the activation record on the server, ensuring that biometric authentication is only possible when it is explicitly enabled.

## Password change

- `/pa/v4/password/change` endpoint
    - Authenticated with "possession_knowledge", `uriId="/pa/password/change"`
    - E2EE, activation scope, `sh1="/pa/password/change"`
    - Request body (before encryption):
      ```json
      {
        "algorithm": "EC_P384_ML_L3",
        "ecdhe": "Base64",
        "mlkem": "Base64"
      }
      ```
    - Response body (before encryption):
      ```json
      {
        "ecdhe": "Base64",
        "mlkem": "Base64"
      }
      ```
    - The result of shared secret calculation is a new factor key stored to `knowledge_factor_key_next` on the server side.

### Full flow

1. User enters old and new PIN/password: `passwordOld`, `passwordNew`

1. Client prepares data for the shared secret:
   ```java
   Pair<SharedSecretRequest, SharedSecretClientContext> requestWithContext = SharedSecret.generateRequestCryptogram();
   return requestWithContext.getFirst();
   ```
1. Client encrypts `SharedSecretRequest` payload with E2EE, activation scope, `sh1="/pa/password/change"`

1. Client sends the encrypted request to `/pa/v4/password/change`. The request is authenticated with PowerAuth V4 authentication code, with `passwordOld`

1. Server verifies authentication code, if valid, then decrypts the payload and then:
   ```java
   // [1] Deduce shared secret
   Pair<SharedSecretResponse, SecretKey> responseWithSecret = ServerSharedSecret.generateResponseCryptogram(request);
   // [2] Store deduced shared secret as a next knowledge factor key.
   activationRecord.setKnowledgeFactorKeyNext(responseWithSecret.getSecond());
   // [3] Return response to the client
   return responseWithSecret.getFirst();
   ```

1. Client receives response from the server and decrypts the response and compute new `KEY_AUTHENTICATION_CODE_KNOWLEDGE`:
   ```java
   SecretKey KEY_AUTHENTICATION_CODE_KNOWLEDGE = SharedSecret.computeSharedSecret(requestWithContext.getSecond(), response);
   ```

1. Store new factor key with using `passwordNew`:
   ```java
   byte[] salt = Generator.randomBytes(32);
   SecretKey kek = KDF.derivePassword(passwordNew, salt);
   byte[] C_KEY_AUTHENTICATION_CODE_KNOWLEDGE = UKE.wrap(KEY_AUTHENTICATION_CODE_KNOWLEDGE, kek);
   // Keep (salt, C_KEY_AUTHENTICATION_CODE_KNOWLEDGE) in persistent storage
   ```

1. Optional: Client can verify the knowledge authentication code by calling `/pa/v4/auth/validate` authenticated with `possession+knowledge`
    - Reason: "CONFIRM_NEW_PASSWORD"

## Biometry setup

- `/pa/v4/biometry/add`
    - Authenticated with "possession_knowledge", `uriId="/pa/biometry/add"`
    - E2EE, activation scope, `sh1="/pa/biometry/add"`
    - Request body (before encryption):
      ```json
      {
        "algorithm": "EC_P384_ML_L3",
        "ecdhe": "Base64",
        "mlkem": "Base64"
      }
      ```
    - Response body (before encryption):
      ```json
      {
        "ecdhe": "Base64",
        "mlkem": "Base64"
      }
      ```
        - The result of shared secret calculation is a new factor key stored to `biometric_factor_key_next` on the server side.

- `/pa/v4/biometry/remove`
    - Authenticated with "possession", `uriId="/pa/biometry/remove"`
    - Request body
      ```json
      {}
      ```
    - Response body
      ```json
      {}
      ```

### Full flow (add)

1. User enters current PIN/password: `password`

1. Client prepares data for the shared secret:
   ```java
   Pair<SharedSecretRequest, SharedSecretClientContext> requestWithContext = SharedSecret.generateRequestCryptogram();
   return requestWithContext.getFirst();
   ```
1. Client encrypts `SharedSecretRequest` payload with E2EE, activation scope, `sh1="/pa/biometry/add"`

1. Encrypted request is authenticated with `possession+knowledge`, with using `password` for knowledge factor

1. Client sends encrypted and authenticated Request to `/pa/v4/biometry/add`.

1. Server verifies authentication code, if valid, then decrypts the payload and then:
   ```java
   // [1] Deduce shared secret
   Pair<SharedSecretResponse, SecretKey> responseWithSecret = ServerSharedSecret.generateResponseCryptogram(request);
   // [2] Update activation record and store deduced shared secret as a next biometric factor key
   activationRecord.setBiometricFactorEnabled(true);
   if (activationRecord.getBiometricFactorKey() == null) {
      // If current key is null, then update the current key
      activationRecord.setBiometricFactorKey(responseWithSecret.getSecond());
   } else {
      // otherwise update the next key
      activationRecord.setBiometricFactorKeyNext(responseWithSecret.getSecond());
   }
   // [3] Return response to the client
   return responseWithSecret.getFirst();
   ```

1. Client receives response from the server and decrypts the response and compute new `KEY_AUTHENTICATION_CODE_BIOMETRY`:
   ```java
   SecretKey KEY_AUTHENTICATION_CODE_BIOMETRY = SharedSecret.computeSharedSecret(requestWithContext.getSecond(), response);
   ```

1. Store new factor key with using appropriate KEK:
   ```java
   // iOS: Generate new KEK and store it to the keychain item with biometric protection
   // Android: Generate new KEK and encrypt it with RSA, or derive new KEK by using AES KDF
   SecretKey kek;
   // 
   byte[] C_KEY_AUTHENTICATION_CODE_BIOMETRY = UKE.wrap(KEY_AUTHENTICATION_CODE_BIOMETRY, kek);
   // Keep C_KEY_AUTHENTICATION_CODE_BIOMETRY in persistent storage
   ```

1. Optional: Client can verify the biometry authentication code by calling `/pa/v4/auth/validate` authenticated with `possession+biometry`
    - Reason: "CONFIRM_BIOMETRY_ADD"

### Full flow (remove)

1. Client removes local KEK protecting `KEY_AUTHENTICATION_CODE_BIOMETRY`
    - On iOS: Remove key from keychain
    - On Android: Remove key from KeyStore
    - Remove `C_KEY_AUTHENTICATION_CODE_BIOMETRY` from the persistent storage

1. Request to `/pa/v4/biometry/remove` is authenticated with `possession` factor

1. Server verifies authentication code, if valid, then
   ```java
   // [1] Update database    
   activationRecord.setBiometricFactorEnabled(false);
   activationRecord.setBiometricFactorKey(null);
   activationRecord.setBiometricFactorKeyNext(null);
   ```
