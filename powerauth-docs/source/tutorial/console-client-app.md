# Using PowerAuth 2.0 Reference Client

This brief chapter serves as a documentation of the reference PowerAuth 2.0 Client - a simple utility connecting to the standard RESTful API.

## Downloading PowerAuth 2.0 Reference Client

You can download the latest `powerauth-java-cmd.jar` at the releases page:

- https://github.com/lime-company/lime-security-powerauth/releases

## Basic usage

PowerAuth 2.0 Reference Client is called as any Java application that is packaged as a JAR file and it uses following command-line arguments.

```
_____                   _____     _   _      ___   ___
|  _  |___ _ _ _ ___ ___|  _  |_ _| |_| |_   |_  | |   |
|   __| . | | | | -_|  _|     | | |  _|   |  |  _|_| | |
|__|  |___|_____|___|_| |__|__|___|_| |_|_|  |___|_|___|


usage: java -jar powerauth-java-cmd.jar
 -a,--activation-code <arg>   In case a specified method is 'prepare',
                              this field contains the activation key (a
                              concatenation of a short activation ID and
                              activation OTP)
 -c,--config-file <arg>       Specifies a path to the config file with
                              Base64 encoded server master public key,
                              application ID and application secret
 -d,--data-file <arg>         In case a specified method is 'sign', this
                              field specifies a file with the input data
                              to be signed and verified with the server,
                              as specified in PowerAuth signature process.
 -e,--endpoint <arg>          In case a specified method is 'sign', this
                              field specifies a URI identifier, as
                              specified in PowerAuth signature process.
 -h,--help                    Print this help manual
 -l,--signature-type <arg>    In case a specified method is 'sign', this
                              field specifies a signature type, as
                              specified in PowerAuth signature process.
 -m,--method <arg>            What API method to call, available names are
                              'prepare', 'status', 'remove' and 'sign'
 -p,--password <arg>          Password used for a knowledge related key
                              encryption. If not specified, an interactive
                              input is required.
 -s,--status-file <arg>       Path to the file with the activation status,
                              serving as the data persistence.
 -t,--http-method <arg>       In case a specified method is 'sign', this
                              field specifies a HTTP method, as specified
                              in PowerAuth signature process.
 -u,--url <arg>               Base URL of the PowerAuth 2.0 Standard
                              RESTful API
```
## Config and status files

Command-line version of a reference PowerAuth 2.0 Client uses two files:

- **Config file** - Basic client configuration file with information that would normally be bundled with a client application. The file stores application ID, application secret and base64 encoded master public key.
- **Status file** - File that keeps the current PowerAuth 2.0 Client status.

### Example of a config file

```json
{
  "applicationName": "PowerAuth 2.0 Reference Client",
  "applicationId": "a1c97807-795a-466e-87bf-230d8ac1451e",
  "applicationSecret": "d358e78a-8d12-4595-bf69-6eff2c2afc04",
  "masterPublicKey": "BCJjw2bvI2+AN61Gwnx0axdLlDtUzSjx2FWklNnsN/Rbi2QDm7oIrCnMrz0s4RgE18KQC2gukK/bCzkDY+bR9bk="
}
```

### Example of a status file

```json
{
  "activationId" : "cebb3ae6-f774-4b74-8020-f7b4da64de8f",
  "serverPublicKey" : "BKVanyqfLG2MxVwMt/LhmFliqPpHxVhtU3PEMG9FOIeJFkPAQjHpije029//S+bOprC4j6a8DMukxfoYkCFfLjU=",
  "counter" : 10,
  "encryptedDevicePrivateKey" : "HxRPkVVTM3QL+hecOY6cwQNvgNzvp2GbvvQ7cAOUXxzAk1dDaZVh1hd+2k18ZHn2",
  "signatureBiometryKey" : "4Kb+7AO49ZHOpA4vtYzZGA==",
  "signatureKnowledgeKeyEncrypted" : "i0LTZsWPlmRel0L7eg8U2w==",
  "signatureKnowledgeKeySalt" : "J/LULF2V/fqE7Dw7AZhlmA==",
  "signaturePossessionKey" : "jO89IxZs9bawvW3qlNQCzg==",
  "transportMasterKey" : "kOh0lamazBJgDLSIcZ/ZJw=="
}
```

## Usage examples

### Prepare activation

Use the `prepare` method to activate a PowerAuth 2.0 Reference client by calling the PowerAuth 2.0 Standard RESTful API endpoint `/pa/activation/create` hosted on root URL `http://localhost:8080/powerauth-restful-server` with activation code `F3CCT-FNOUS-GEVJF-O3HMV`. Read and store the client status from the `/tmp/pa_status.json` file. Use master public key stored in the `/tmp/pamk.json` file. Store the knowledge related derived key using a given password `1234`.

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to encrypt the knowledge related signature key._

```bash
java -jar powerauth-java-cmd.jar --url "http://localhost:8080/powerauth-restful-server" --status-file "/tmp/pa_status.json" --config-file "/tmp/pamk.json" --method "prepare" --password "1234" --activation-code "F3CCT-FNOUS-GEVJF-O3HMV"
```

### Get activation status

Use the `status` method to get the activation status for the activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth 2.0 Standard RESTful API endpoint `/pa/activation/status` hosted on root URL `http://localhost:8080/powerauth-restful-server`. Use master public key stored in the `/tmp/pamk.json` file.

```bash
java -jar powerauth-java-cmd.jar --url "http://localhost:8080/powerauth-restful-server" --status-file "/tmp/pa_status.json" --config-file "/tmp/pamk.json" --method "status"
```

### Remove the activation

Use the `remove` method to remove activation with an activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth 2.0 Standard RESTful API endpoint `/pa/activation/remove` hosted on root URL `http://localhost:8080/powerauth-restful-server`. Use master public key stored in the `/tmp/pamk.json` file. Unlock the knowledge related derived key using `1234` as a password.

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge related signature key._

```bash
java -jar powerauth-java-cmd.jar --url "http://localhost:8080/powerauth-restful-server" --status-file "/tmp/pa_status.json" --config-file "/tmp/pamk.json" --method "remove" --password "1234"
```

### Validate the signature

Use the `sign` method to verify a signature for given data using activation record associated with an activation ID stored in the status file `/tmp/pa_status.json`. Call an authenticated endpoint `http://localhost:8080/powerauth-restful-server/pa/signature/validate` that is identified by an identifier `/pa/signature/validate` (the same as the endpoint name after the main context). Use master public key stored in the `/tmp/pamk.json` file. Use HTTP method `POST`, use `possession_knowledge` signature type and take the request data from a file `/tmp/request.json`. Unlock the knowledge related derived key using `1234` as a password.

_Note: If a `--password` option is not provided, this method requires interactive console input of the password, in order to unlock the knowledge related signature key._

```bash
java -jar powerauth-java-cmd.jar --url "http://localhost:8080/powerauth-restful-server/pa/signature/validate" --status-file "/Users/petrdvorak/pa_status.json" --config-file "/Users/petrdvorak/pamk.json" --method "sign" --http-method "POST"  --endpoint "/pa/signature/validate" --signature-type "possession_knowledge" --data-file "/tmp/request.json"
```
