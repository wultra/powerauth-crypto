# PowerAuth 2.0 Database Structure

PowerAuth 2.0 Server uses a very simple database structure that can be recreated in any SQL database (in order to work with PowerAuth 2.0 Server, the database must be JPA ready).

You can see the overall database schema in this [MySQL Workbench file](https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/sql/mysql/mysql-workbench-model.mwb):

<img src="https://github.com/lime-company/lime-security-powerauth/blob/master/powerauth-docs/export/powerauth-db-mysql-workbench.png" alt="PowerAuth 2.0 Server Database Schema"/>

## Table Documentation

This chapter explains individual tables and their columns. The column types are used from MySQL dialect, other databases use types that are equivalent (mapping is usually straight forward).

### Applications Table

Table name: `pa_application`

Purpose: Stores applications used in the PowerAuth 2.0 Server.

Columns:

| Name | Type | Info | Note |
|------|------|---------|------|
| id | BIGINT(20) | autoincrement | Unique application ID. |
| name | VARCHAR[255] | - | Application name, for example "Mobile Banking". |

### Application Versions Table

Table name: `pa_application_version`

Purpose: Stores application versions for the applications stored in `pa_application` table.

Columns:

| Name | Type | Info | Note |
|------|------|---------|------|
| id | BIGINT(20)  | primary key, autoincrement | Unique application version identifier. |
| application_id | BIGINT(20)  | foreign key: pa\_application.id | Related application ID. |
| name | VARCHAR(255) | - | Version name. |
| application_key | VARCHAR(255) | index | Application key related to this version. Should be indexed to allow a fast lookup, since this is an identifier client applications use. |
| application_secret | VARCHAR(255) | - | Application secret related to this version. |
| supported | INT(11) | - | Flag indicating if this version is supported or not (0 = not supported, 1..N = supported) |

### Activations Table

Table name: `pa_activation`

Purpose: Stores activations. Activation is a unit associating signature / transport and encryption keys to a specific user and application.

Columns:

| Name | Type | Info | Note |
|------|------|---------|------|
| activation_id  | VARCHAR(37) | primary key, UUID (level 4) | Unique activation ID. Uses UUID Level 4 format, for example "099e5e30-47b1-41c7-b49b-3bf28e811fca". |
| activation_id_short | VARCHAR(255) | index | Short activation ID used during the activation process. Uses 2x5 characters in Base32 encoding separated by a "-" character, for example "MRVWC-43KNR". |
| activation_otp  | VARCHAR(255) | - | Activation OTP used for public key encryption. Uses 2x5 characters in Base32 encoding separated by a "-" character, for example "ZWUYL-ENRVG". |
| activation_status  | INT(11) | - | Activation status, can be one of following values:<br><br>1 - CREATED<br>2 - OTP_USED<br>3 - ACTIVE<br>4 - BLOCKED<br>5 - REMOVED |
| activation_name  | VARCHAR(255 | - | Name of the activation, typically a name of the client device, for example "John's iPhone 6" |
| application_id  | BIGINT(20) | foreign key: pa\_application.id | Associated application ID. |
| user_id  | VARCHAR(255) | index | Associated user ID. |
| extras  | TEXT | - | Any application specific information. |
| counter  | BIGINT(20) | - | Activation counter. |
| device_public_key_base64  | TEXT | - | Device public key, encoded in Base64 encoding. |
| failed_attempts  | BIGINT(20) | - | Number of failed signature verification attempts. |
| max_failed_attempts | BIGINT(20) | - | Number of maximum allowed failed signature verification attempts. After value of "failed_attempts" matches this value, activation becomes blocked (activation_status = 4, BLOCKED) |
| server_private_key_base64 | TEXT | - | Server private key, encoded as Base64 |
| server_public_key_base64 | TEXT | - | Server public key, encoded as Base64 |
| master_keypair_id | BIGINT(20) | foreign key: pa\_master\_keypair.id | Master Key Pair identifier, used during the activation process |
| timestamp_created | DATETIME | - | Timestamp of the record creation. |
| timestamp_activation_expire | DATETIME | - | Timestamp until which the activation must be committed. In case activation is not committed until this period, it will become REMOVED. |
| timestamp_last_used | DATETIME | - | Timestamp of the last signature verification attempt. |

### Master Key Pair Table

Table name: `pa_master_keypair`

Purpose: Stores master key pairs associated with applications and used during the activation process.

Columns:

| Name | Type | Info | Note |
|------|------|---------|------|
| id | BIGINT(20) | primary key, autoincrement | Unique master key pair ID. |
| application_id | BIGINT(20) | foreign key: pa\_application.id | Associated application ID. |
| name | VARCHAR(255) | - | Name of the key pair. |
| master_key_private_base64 | TEXT | - | Private key encoded as Base64 |
| master_key_public_base64 | TEXT | - | Public key encoded as Base64 |
| timestamp_created | DATETIME | - | Timestamp of creation. |

### Signature Audit Records Table

Table name: `pa_signature_audit`

Purpose: Stores records with values used for attempts for the signature validation.

Columns:

| Name | Type | Info | Note |
|------|------|---------|------|
| id | BIGINT(20) | primary key, autoincrement | Unique record ID. |
| activation_id | BIGINT(20) | foreign key: pa\_activation.activation\_id | Associated activation ID. |
| activation_counter | BIGINT(20) | - | Activation counter at the moment of signature validation. |
| activation_status | INT(11) | - | Activation status at the moment of signature validation. |
| data_base64 | TEXT | - | Data passed as the base for the signature, encoded as Base64. |
| signature_type | VARCHAR(255) | - | Requested type of the signature. |
| signature | VARCHAR(255) | - | Provided value of the signature. |
| valid | INT(11) | - | Flag indicating if the provided signature was valid. |
| note | TEXT | - | Additional information about the validation result. |
| timestamp_created | DATETIME | - | A timestamp of the validation attempt. |
