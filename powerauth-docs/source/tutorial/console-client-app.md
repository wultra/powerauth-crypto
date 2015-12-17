# Using PowerAuth 2.0 Reference Client

This brief chapter serves as a documentation of the reference PowerAuth 2.0 Client - a simple utility connecting to the standard RESTful API.

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
 -e,--endpoint <arg>          In case a specified method is 'sign', this
                              field specifies a URI identifier, as
                              specified in PowerAuth signature process.
 -h,--http-method <arg>       In case a specified method is 'sign', this
                              field specifies a HTTP method, as specified
                              in PowerAuth signature process.
 -i,--input-file <arg>        In case a specified method is 'sign', this
                              field specifies a file with the input data
                              to be signed and verified with the server,
                              as specified in PowerAuth signature process.
 -k,--master-key-file <arg>   Specifies a path to the file with Base64
                              encoded server master public key
 -l,--application-id <arg>    In case a specified method is 'sign', this
                              field specifies an application ID, as
                              specified in PowerAuth signature process.
 -m,--method <arg>            What API method to call, available names are
                              'prepare', 'status', 'remove', 'sign' and
                              'unlock'
 -s,--status-file <arg>       Path to the file with the activation status,
                              serving as the data persistence.
 -u,--url <arg>               Base URL of the PowerAuth 2.0 Standard
                              RESTful API
```

## Usage examples

### Prepare activation

Use the `prepare` method to activate a PowerAuth 2.0 Reference client by calling the PowerAuth 2.0 Standard RESTful API endpoint `/pa/activation/create` hosted on root URL `http://localhost:8080/powerauth-restful-server` with activation code `F3CCT-FNOUS-GEVJF-O3HMV`. Read and store the client status from the `/tmp/pa_status.json` file. Use master public key stored in the `/tmp/pamk.txt` file.

```bash
java -jar powerauth-java-cmd.jar --url "http://localhost:8080/powerauth-restful-server" --status-file "/tmp/pa_status.json" --master-key-file "/tmp/pamk.txt" --method "prepare" --activation-code "F3CCT-FNOUS-GEVJF-O3HMV"
```

### Get activation status

Use the `status` method to get the activation status for the activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth 2.0 Standard RESTful API endpoint `/pa/activation/status` hosted on root URL `http://localhost:8080/powerauth-restful-server`. Use master public key stored in the `/tmp/pamk.txt` file.

```bash
java -jar powerauth-java-cmd.jar --url "http://localhost:8080/powerauth-restful-server" --status-file "/tmp/pa_status.json" --master-key-file "/tmp/pamk.txt" --method "status"
```

### Remove the activation

Use the `remove` method to get the activation status for the activation ID stored in the status file `/tmp/pa_status.json`, by calling the PowerAuth 2.0 Standard RESTful API endpoint `/pa/activation/remove` hosted on root URL `http://localhost:8080/powerauth-restful-server`. Use master public key stored in the `/tmp/pamk.txt` file.

This method requires interactive console input of the password, in order to unlock the knowledge related signature key.

```bash
java -jar powerauth-java-cmd.jar --url "http://localhost:8080/powerauth-restful-server" --status-file "/tmp/pa_status.json" --method "remove" --master-key-file "/tmp/pamk.txt"
```
