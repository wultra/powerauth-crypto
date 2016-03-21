--
-- Create tables for applications and application versions
--

--
-- Create tables for applications and application versions
--

CREATE TABLE pa_application (
  id bigint NOT NULL AUTO_INCREMENT,
  name varchar(255) DEFAULT NULL,
  PRIMARY KEY (id)
);

CREATE TABLE pa_application_version (
  id bigint NOT NULL AUTO_INCREMENT,
  application_id bigint NOT NULL,
  name varchar(255) DEFAULT NULL,
  application_key varchar(255) DEFAULT NULL,
  application_secret varchar(255) DEFAULT NULL,
  supported int DEFAULT NULL,
  PRIMARY KEY (id),
  CONSTRAINT FK_APPLICATION_VERSION FOREIGN KEY (application_id) REFERENCES pa_application (id) ON DELETE CASCADE ON UPDATE NO ACTION
);

CREATE INDEX KEY_APPLICATION_ID ON pa_application_version (application_id);
CREATE INDEX KEY_APPLICATION_KEY ON pa_application_version (application_key);

--
-- Create table for application related master keypair
--

CREATE TABLE pa_master_keypair (
  id bigint NOT NULL AUTO_INCREMENT,
  application_id bigint NOT NULL,
  name varchar(255) DEFAULT NULL,
  master_key_private_base64 varchar(255) NOT NULL,
  master_key_public_base64 varchar(255) NOT NULL,
  timestamp_created datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT FK_APPLICATION_KEYPAIR FOREIGN KEY (application_id) REFERENCES pa_application (id) ON DELETE CASCADE ON UPDATE NO ACTION
);

CREATE INDEX FK_APPLICATION_KEYPAIR_idx ON pa_master_keypair (application_id);

--
-- Create table for activation records
--

CREATE TABLE pa_activation (
  activation_id varchar(37) NOT NULL,
  activation_id_short varchar(255) NOT NULL,
  activation_otp varchar(255) NOT NULL,
  activation_status int NOT NULL,
  activation_name varchar(255) DEFAULT NULL,
  application_id bigint NOT NULL,
  user_id varchar(255) NOT NULL,
  extras clob,
  counter bigint NOT NULL,
  device_public_key_base64 clob,
  failed_attempts bigint DEFAULT NULL,
  max_failed_attempts bigint NOT NULL DEFAULT '5',
  server_private_key_base64 clob NOT NULL,
  server_public_key_base64 clob NOT NULL,
  master_keypair_id bigint DEFAULT NULL,
  timestamp_created datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  timestamp_activation_expire datetime NOT NULL,
  timestamp_last_used datetime NOT NULL,
  PRIMARY KEY (activation_id),
  CONSTRAINT FK_ACTIVATION_APPLICATION FOREIGN KEY (application_id) REFERENCES pa_application (id) ON DELETE CASCADE ON UPDATE NO ACTION
);

CREATE INDEX FK_ACTIVATION_APPLICATION_idx ON pa_activation (application_id);

--
-- Create a table for signature audits
--

CREATE TABLE pa_signature_audit (
  id int NOT NULL AUTO_INCREMENT,
  activation_id varchar(37) NOT NULL,
  activation_counter bigint NOT NULL,
  activation_status int NOT NULL,
  data_base64 clob,
  signature_type varchar(255) NOT NULL,
  signature varchar(255) NOT NULL,
  valid int NOT NULL DEFAULT '0',
  note clob NOT NULL,
  timestamp_created datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT FK_ACTIVATION_ID FOREIGN KEY (activation_id) REFERENCES pa_activation (activation_id) ON DELETE CASCADE ON UPDATE NO ACTION
);

CREATE INDEX K_ACTIVATION_ID ON pa_signature_audit (activation_id);
