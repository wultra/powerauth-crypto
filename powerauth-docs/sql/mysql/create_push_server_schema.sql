CREATE TABLE `push_app_credentials` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `app_id` int(11) DEFAULT NULL,
  `ios` blob,
  `ios_bundle` varchar(255) DEFAULT NULL,
  `android` text,
  `android_bundle` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `app_id_index` (`app_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

CREATE TABLE `push_device_registration` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `activation_id` varchar(37) DEFAULT NULL,
  `user_id` varchar(255) DEFAULT NULL,
  `app_id` int(11) DEFAULT NULL,
  `platform` varchar(20) DEFAULT NULL,
  `push_token` varchar(255) DEFAULT NULL,
  `last_registered` varchar(45) DEFAULT NULL,
  `is_active` int(11) DEFAULT NULL,
  `encryption_key` text,
  `encryption_key_index` text,
  PRIMARY KEY (`id`),
  KEY `activation_id_index` (`activation_id`),
  KEY `user_id_index` (`user_id`),
  KEY `app_id_index` (`app_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

CREATE TABLE `push_message` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `device_registration_id` int(11) DEFAULT NULL,
  `user_id` varchar(255) DEFAULT NULL,
  `activation_id` varchar(37) DEFAULT NULL,
  `silent` int(11) DEFAULT NULL,
  `personal` int(11) DEFAULT NULL,
  `encrypted` int(11) DEFAULT NULL,
  `message_body` text,
  `timestamp_created` datetime DEFAULT NULL,
  `status` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `USER_ID_INDEX` (`user_id`,`activation_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
