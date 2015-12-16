-- MySQL dump 10.13  Distrib 5.6.22, for osx10.8 (x86_64)
--
-- Host: localhost    Database: powerauth
-- ------------------------------------------------------
-- Server version	5.6.23

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `pa_activation`
--

DROP TABLE IF EXISTS `pa_activation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pa_activation` (
  `activation_id` varchar(37) NOT NULL,
  `activation_id_short` varchar(255) NOT NULL,
  `activationotp` varchar(255) NOT NULL,
  `activation_status` int(11) NOT NULL,
  `activation_name` varchar(255) DEFAULT NULL,
  `extras` text DEFAULT NULL,
  `counter` bigint(20) NOT NULL,
  `device_public_key_base64` text,
  `failed_attempts` bigint(20) DEFAULT NULL,
  `server_private_key_base64` text NOT NULL,
  `server_public_key_base64` text NOT NULL,
  `timestamp_created` datetime NOT NULL,
  `timestamp_last_used` datetime NOT NULL,
  `user_id` varchar(255) NOT NULL,
  `master_keypair_id` bigint(20) NOT NULL,
  PRIMARY KEY (`activation_id`),
  KEY `FK_6qiteby9oxe0lum196431bg7w` (`master_keypair_id`),
  CONSTRAINT `FK_6qiteby9oxe0lum196431bg7w` FOREIGN KEY (`master_keypair_id`) REFERENCES `pa_master_keypair` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2015-11-18 23:28:42
