# Shared Secret Derivation

This document defines a `SharedSecret` interface responsible for deriving shared secret information on both sides of the communication. The document also contains a specification for ECDHE-KEM.

The `SharedSecret` interface is using the following entities:

- `SharedSecretRequest` an object representing a request data generated on the client and received by the server.
- `SharedSecretResponse` an object representing a response data generated on the server and received by the client.
- `SharedSecretClientContext` is object representing a data required for proper shared secret deduction on the client. The object is defined as `List<PrivateKey>`.

### Request

The `SharedSecretRequest` object contains the following properties:

| Property          | Type         | Description                                               |
|-------------------|--------------|-----------------------------------------------------------|
| algorithm         | String       | Selected algorithm                                        |
| encapsulationKeys | List<byte[]> | Array with encapsulation keys, each key encoded as Base64 |

### Response

The `SharedSecretResponse` object contains the following properties:

| Property         | Type         | Description                                                   |
|------------------|--------------|---------------------------------------------------------------|
| salt             | byte[]       | Salt used for the shared secret derivation, encoded as Base64 |
| encapsulatedKeys | List<byte[]> | Array with encapsulated keys, each key encoded as Base64      | 

### Algorithm

Input parameters:

- `String VERSION` - protocol version, for example "4.0"
- `String ALGORITHM` - selected algorithm name.
- `List<KEM> KEM_ALGORITHMS`, array of KEM implementations used for the shared secret computation.

Implementation:

- Let's compute common constants:
  ```java
  final String LABEL = "shared-secret/" + ALGORITHM;
  ```

- Let's define the final derivation function that corresponds to [NIST SP 800-56C-rev2](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final):
  ```java
  SecretKey computeSharedSecret(List<SecretKey> secretKeys, byte[] salt) {
    // Concatenate all secrets
    byte[] concatenatedSecrets = ByteUtils.concatWithSizes(secretKeys.toArray(new byte[0][]);
    byte[] fixedInfo = ByteUtils.concatWithSizes(LABEL, VERSION);
    // Due to fact that we always require 256-bits long key, we need just one iteration.
    // This is because output length is equal to KMAC's output length.
    byte[] X = ByteUtils.concat(
      ByteUtils.encode((int)1),   // counter
      concatenatedSecrets,        // || Z
      fixedInfo                   // || fixedInfo
    );
    byte[] custom = ByteUtils.encode("KDF");
    byte[] SHARED_SECRET = Mac.kmac256(salt, X, 32, custom);
    return KeyConversion.secretKeyFromBytes(SHARED_SECRET);
  }
  ```

- `Pair<SharedSecretRequest, SharedSecretClientContext> SharedSecret.generateRequestCryptogram()`
  ```java
  List<PrivateKey> decapsulationKeys = new ArrayList<PrivateKey>();
  List<String> encapsulationKeys = new ArrayList<String>();
  for (KEM kem: KEM_ALGORITHMS) {
      // For each KEM algorithm, do
      KeyPair keyPair = kem.generateKeyPair();
      decapsulationKeys.add(keyPar.getPrivateKey());
      encapsulationKeys.add(KeyConversion.getBytes(keyPair.getPublicKey()));
  }
  SharedSecretRequest request = new SharedSecretRequest();
  request.setAlgorithm(ALGORITHM);
  request.setEncapsulationKeys(encapsulationKeys);
  // decapsulationKeys type is equal to SharedSecretClientContext 
  return new Pair<>(request, decapsulationKeys);
  ```

- `Pair<SharedSecretResponse, SecretKey> ServerSharedSecret.generateResponseCryptogram(SharedSecretRequest request)`
  ```java
  String selectedAlgorithm = request.getAlgorithm();
  List<byte[]> encapsulationKeys = request.getEncapsulationKeys();
  // Input request validation
  if (!selectedAlgorithm.equals(ALGORITHM)) {
      throw Exception("Unexpected algorithm");
  }
  if (encapsulationKeys.size() != KEM_ALGORITHMS.size()) {
      throw Exception("Unexpected count of encapsulation keys");
  }
  // Now iterate over all KEMs and call encapsulate()
  List<SecretKey> secretKeys = new ArrayList<SecretKey>();
  List<byte[]> encapsulatedKeys = new ArrayList<byte[]>();
  for (int i = 0; i < KEM_ALGORITHMS.size(); i++) {
      KEM kem = KEM_ALGORITHMS.get(i);
      PublicKey encapKey = KeyConversion.publicKeyFromBytes(encapsulationKeys.get(i));
      Pair<SecretKey, byte[]> secretWithEncapsulated = kem.encapsulate(encapKey);
      secretKeys.add(secretWithEncapsulated.getFirst());
      encapsulatedKeys.add(secretWithEncapsulated.getSecond());
  }
  // Generate salt
  byte[] salt = Generator.randomBytes(32);
  // Calculate shared secret
  SecretKey sharedSecret = computeSharedSecret(secretKeys, salt);
  // Build response and return...
  SharedSecretResponse response = new SharedSecretResponse();
  response.setSalt(salt);
  response.setEncapsulatedKeys(encapsulatedKeys);
  return new Pair<>(response, sharedSecret);
  ```

- `SecretKey SharedSecret.computeSharedSecret(SharedSecretClientContext context, SharedSecretResponse response)`
  ```java
  List<PrivateKey> decapsulationKeys = context;
  List<byte[]> encapsulatedKeys = response.getEncapsulatedKeys();
  // Input validations
  if (decapsulationKeys.size() != encapsulatedKeys.size() || 
      encapsulatedKeys.size() != KEM_ALGORITHMS.size()) {
      throw Exception("Unexpected count of encapsulated keys");
  }
  // Now iterate over all KEMs and call decapsulate
  List<SecretKey> secretKeys = new ArrayList<SecretKey>();
  for (int i = 0; i < KEM_ALGORITHMS.size(); i++) {
      KEM kem = KEM_ALGORITHMS.get(i);
      SecretKey secretKey = kem.decapsulate(decapsulationKeys.get(i), encapsulatedKeys.get(i));
      secretKeys.add(secretKey);
  }
  // Calculate shared secret
  SecretKey sharedSecret = computeSharedSecret(secretKeys, response.getSalt());
  ```


## SharedSecret configurations

### EC_P384

- ALGORITHM = `"EC_P384"`
- KEM_ALGORITHMS are:
    1. DHKEM(P-384, HKDF-SHA384)

### EC_P384_ML_L3

- ALGORITHM = `"EC_P384_ML_L3"`
- KEM_ALGORITHMS are:
    1. DHKEM(P-384, HKDF-SHA384)
    2. ML-KEM-768

### EC_P384_ML_L5

- ALGORITHM = `"EC_P384_ML_L5"`
- KEM_ALGORITHMS are:
    1. DHKEM(P-384, HKDF-SHA384)
    2. ML-KEM-1024


## DHKEM implementation

DHKEM is specified in [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html#name-dh-based-kem-dhkem). We're using HPKE in "base mode".
