--
-- Table structure for table `pa_master_keypair`
--

CREATE TABLE `pa_master_keypair` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `master_key_private_base64` varchar(255) NOT NULL,
  `master_key_public_base64` varchar(255) NOT NULL,
  `timestamp_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

--
-- Table structure for table `pa_activation`
--

CREATE TABLE `pa_activation` (
  `activation_id` varchar(37) NOT NULL,
  `activation_id_short` varchar(255) NOT NULL,
  `activation_otp` varchar(255) NOT NULL,
  `activation_status` int(11) NOT NULL,
  `activation_name` varchar(255) DEFAULT NULL,
  `extras` text DEFAULT NULL,
  `counter` bigint(20) NOT NULL,
  `device_public_key_base64` text,
  `failed_attempts` bigint(20) DEFAULT NULL,
  `max_failed_attempts` bigint(20) NOT NULL DEFAULT '5',
  `server_private_key_base64` text NOT NULL,
  `server_public_key_base64` text NOT NULL,
  `timestamp_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `timestamp_activation_expire` datetime NOT NULL,
  `timestamp_last_used` datetime NOT NULL,
  `user_id` varchar(255) NOT NULL,
  `master_keypair_id` bigint(20) NOT NULL,
  PRIMARY KEY (`activation_id`),
  KEY `K_MASTER_KEYPAIR_ID` (`master_keypair_id`),
  CONSTRAINT `FK_MASTER_KEYPAIR_ID` FOREIGN KEY (`master_keypair_id`) REFERENCES `pa_master_keypair` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `pa_signature_audit`
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
