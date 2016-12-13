--
-- Create tables for applications and application versions
--

CREATE TABLE `pa_application` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

CREATE TABLE `pa_application_version` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `application_id` bigint(20) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `application_key` varchar(255) DEFAULT NULL,
  `application_secret` varchar(255) DEFAULT NULL,
  `supported` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `KEY_APPLICATION_ID` (`application_id`),
  KEY `KEY_APPLICATION_KEY` (`application_key`),
  CONSTRAINT `FK_APPLICATION_VERSION` FOREIGN KEY (`application_id`) REFERENCES `pa_application` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

--
-- Create table for application related master keypair
--

CREATE TABLE `pa_master_keypair` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `application_id` bigint(20) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `master_key_private_base64` varchar(255) NOT NULL,
  `master_key_public_base64` varchar(255) NOT NULL,
  `timestamp_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `FK_APPLICATION_KEYPAIR_idx` (`application_id`),
  CONSTRAINT `FK_APPLICATION_KEYPAIR` FOREIGN KEY (`application_id`) REFERENCES `pa_application` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

--
-- Create table for activation records
--

CREATE TABLE `pa_activation` (
  `activation_id` varchar(37) NOT NULL,
  `activation_id_short` varchar(255) NOT NULL,
  `activation_otp` varchar(255) NOT NULL,
  `activation_status` int(11) NOT NULL,
  `activation_name` varchar(255) DEFAULT NULL,
  `application_id` bigint(20) NOT NULL,
  `user_id` varchar(255) NOT NULL,
  `extras` text,
  `counter` bigint(20) NOT NULL,
  `device_public_key_base64` text,
  `failed_attempts` bigint(20) DEFAULT NULL,
  `max_failed_attempts` bigint(20) NOT NULL DEFAULT '5',
  `server_private_key_base64` text NOT NULL,
  `server_public_key_base64` text NOT NULL,
  `master_keypair_id` bigint(20) DEFAULT NULL,
  `timestamp_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `timestamp_activation_expire` datetime NOT NULL,
  `timestamp_last_used` datetime NOT NULL,
  PRIMARY KEY (`activation_id`),
  KEY `FK_ACTIVATION_APPLICATION_idx` (`application_id`),
  CONSTRAINT `FK_ACTIVATION_APPLICATION` FOREIGN KEY (`application_id`) REFERENCES `pa_application` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Create a table for signature audits
--

CREATE TABLE `pa_signature_audit` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `activation_id` varchar(37) NOT NULL,
  `activation_counter` bigint(20) NOT NULL,
  `activation_status` int(11) NOT NULL,
  `data_base64` text,
  `signature_type` varchar(255) NOT NULL,
  `signature` varchar(255) NOT NULL,
  `valid` int(11) NOT NULL DEFAULT '0',
  `note` text NOT NULL,
  `timestamp_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `K_ACTIVATION_ID` (`activation_id`),
  CONSTRAINT `FK_ACTIVATION_ID` FOREIGN KEY (`activation_id`) REFERENCES `pa_activation` (`activation_id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

--
-- Create a table for integration credentials
--

CREATE TABLE `pa_integration` (
  `id` varchar(37) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `client_token` varchar(37) DEFAULT NULL,
  `client_secret` varchar(37) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Create a table for callback URLs
--

CREATE TABLE `pa_application_callback` (
  `id` varchar(37) NOT NULL,
  `application_id` bigint(20) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `callback_url` text NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
