-- MySQL dump 10.13  Distrib 8.0.19, for Win64 (x86_64)
--
-- Host: localhost    Database: medicare
-- ------------------------------------------------------
-- Server version	9.3.0

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `appointments`
--

DROP TABLE IF EXISTS `appointments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `appointments` (
  `id` char(36) NOT NULL,
  `patient_id` char(36) NOT NULL,
  `doctor_id` char(36) NOT NULL,
  `time_slot_id` char(36) NOT NULL,
  `status` enum('booked','completed','canceled') NOT NULL,
  `notes` text,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `time_slot_id` (`time_slot_id`),
  KEY `fk_appointment_patient` (`patient_id`),
  KEY `fk_appointment_doctor` (`doctor_id`),
  CONSTRAINT `fk_appointment_doctor` FOREIGN KEY (`doctor_id`) REFERENCES `doctors` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_appointment_patient` FOREIGN KEY (`patient_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_appointment_time_slot` FOREIGN KEY (`time_slot_id`) REFERENCES `time_slots` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `appointments`
--

LOCK TABLES `appointments` WRITE;
/*!40000 ALTER TABLE `appointments` DISABLE KEYS */;
INSERT INTO `appointments` VALUES ('1942bf21-83d3-11f0-9b0d-00e04c688aa3','c8ce521e-82f8-11f0-9b0d-00e04c688aa3','22b63471-83bf-11f0-9b0d-00e04c688aa3','47606809-83d1-11f0-9b0d-00e04c688aa3','booked','','2025-08-28 05:51:53','2025-08-28 05:51:53'),('76e10112-8571-11f0-9b0d-00e04c688aa3','14bdad33-8571-11f0-9b0d-00e04c688aa3','22b63471-83bf-11f0-9b0d-00e04c688aa3','3c1b6c11-8571-11f0-9b0d-00e04c688aa3','booked','','2025-08-30 07:18:02','2025-08-30 07:18:02'),('a797b0b6-855f-11f0-9b0d-00e04c688aa3','c8ce521e-82f8-11f0-9b0d-00e04c688aa3','22b63471-83bf-11f0-9b0d-00e04c688aa3','28f23f6d-854d-11f0-9b0d-00e04c688aa3','booked','','2025-08-30 05:10:32','2025-08-30 05:10:32'),('b3f371e5-83d5-11f0-9b0d-00e04c688aa3','c8ce521e-82f8-11f0-9b0d-00e04c688aa3','22b63471-83bf-11f0-9b0d-00e04c688aa3','a7576b8e-83cf-11f0-9b0d-00e04c688aa3','booked','','2025-08-28 06:10:31','2025-08-28 06:10:31'),('f0202317-83d1-11f0-9b0d-00e04c688aa3','c8ce521e-82f8-11f0-9b0d-00e04c688aa3','22b63471-83bf-11f0-9b0d-00e04c688aa3','1007d7f0-83cf-11f0-9b0d-00e04c688aa3','booked','ท้องเสีย','2025-08-28 05:43:34','2025-08-28 05:43:34');
/*!40000 ALTER TABLE `appointments` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `doctors`
--

DROP TABLE IF EXISTS `doctors`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `doctors` (
  `id` char(36) NOT NULL,
  `user_id` char(36) NOT NULL,
  `specialty` varchar(100) NOT NULL,
  `license_number` varchar(50) DEFAULT NULL,
  `bio` text,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_id` (`user_id`),
  CONSTRAINT `fk_doctor_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `doctors`
--

LOCK TABLES `doctors` WRITE;
/*!40000 ALTER TABLE `doctors` DISABLE KEYS */;
INSERT INTO `doctors` VALUES ('18875125-83c5-11f0-9b0d-00e04c688aa3','60d2f3eb-83c4-11f0-9b0d-00e04c688aa3','อายุรกรรม',NULL,NULL,'2025-08-28 04:11:39','2025-08-28 04:11:39'),('22b63471-83bf-11f0-9b0d-00e04c688aa3','22b5e022-83bf-11f0-9b0d-00e04c688aa3','อายุรกรรม','Test','นายแพทย์นพชัย ชัยพินิจ ชื่อเล่นชื่อเฟียส เป็นหมออันดับหนึ่งของโรงพยาบาล','2025-08-28 03:28:59','2025-08-30 07:10:25'),('5e97904d-8564-11f0-9b0d-00e04c688aa3','5e976d82-8564-11f0-9b0d-00e04c688aa3','กุมารเวชศาสตร์โรคปอดและระบบหายใจ',NULL,NULL,'2025-08-30 05:44:17','2025-08-30 05:44:17'),('c2f968cf-8571-11f0-9b0d-00e04c688aa3','c2f9445c-8571-11f0-9b0d-00e04c688aa3','กระดูก','MAKE1234','นายแพทย์กิตติภพ จิรพณิชกุล หมอเชี่ยวชาญด้านกระดูกเบอร์1 ของประเทศไทย','2025-08-30 07:20:09','2025-08-30 07:22:01');
/*!40000 ALTER TABLE `doctors` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `time_slots`
--

DROP TABLE IF EXISTS `time_slots`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `time_slots` (
  `id` char(36) NOT NULL,
  `doctor_id` char(36) NOT NULL,
  `start_time` datetime NOT NULL,
  `end_time` datetime NOT NULL,
  `is_booked` tinyint(1) NOT NULL DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `fk_time_slot_doctor` (`doctor_id`),
  CONSTRAINT `fk_time_slot_doctor` FOREIGN KEY (`doctor_id`) REFERENCES `doctors` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `time_slots`
--

LOCK TABLES `time_slots` WRITE;
/*!40000 ALTER TABLE `time_slots` DISABLE KEYS */;
INSERT INTO `time_slots` VALUES ('1007d7f0-83cf-11f0-9b0d-00e04c688aa3','22b63471-83bf-11f0-9b0d-00e04c688aa3','2025-08-28 13:00:00','2025-08-28 17:00:00',1,'2025-08-28 05:22:59','2025-08-28 05:43:34'),('28f23f6d-854d-11f0-9b0d-00e04c688aa3','22b63471-83bf-11f0-9b0d-00e04c688aa3','2025-08-30 09:57:00','2025-08-30 11:00:00',1,'2025-08-30 02:58:09','2025-08-30 05:10:32'),('3c1b6c11-8571-11f0-9b0d-00e04c688aa3','22b63471-83bf-11f0-9b0d-00e04c688aa3','2025-08-30 15:30:00','2025-08-30 16:30:00',1,'2025-08-30 07:16:23','2025-08-30 07:18:02'),('47606809-83d1-11f0-9b0d-00e04c688aa3','22b63471-83bf-11f0-9b0d-00e04c688aa3','2025-08-28 13:00:00','2025-08-28 14:00:00',1,'2025-08-28 05:38:51','2025-08-28 05:51:53'),('90339203-83ce-11f0-9b0d-00e04c688aa3','22b63471-83bf-11f0-9b0d-00e04c688aa3','2025-08-28 12:22:00','2025-08-29 12:22:00',1,'2025-08-28 05:19:25','2025-08-28 05:22:22'),('a7576b8e-83cf-11f0-9b0d-00e04c688aa3','22b63471-83bf-11f0-9b0d-00e04c688aa3','2025-09-01 09:30:00','2025-09-01 10:30:00',1,'2025-08-28 05:27:13','2025-08-28 06:10:31'),('dc06198a-8571-11f0-9b0d-00e04c688aa3','c2f968cf-8571-11f0-9b0d-00e04c688aa3','2025-08-30 14:20:00','2025-08-30 14:50:00',0,'2025-08-30 07:20:51','2025-08-30 07:20:51'),('e24c202f-8571-11f0-9b0d-00e04c688aa3','c2f968cf-8571-11f0-9b0d-00e04c688aa3','2025-08-30 16:25:00','2025-08-30 19:25:00',0,'2025-08-30 07:21:02','2025-08-30 07:21:02');
/*!40000 ALTER TABLE `time_slots` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` char(36) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `full_name` varchar(255) NOT NULL,
  `email` varchar(255) DEFAULT NULL,
  `phone_number` varchar(20) DEFAULT NULL,
  `address` text,
  `role` enum('patient','doctor','admin') NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES ('14bdad33-8571-11f0-9b0d-00e04c688aa3','saranya','$2b$10$mgqxukHs37KkPdXIFFPg8uTt0xtrsRj1dJPWKuqMhw4pmETbLeOtq','สรัญญา ฉิมสอน','saranya@gmail.com','0987654321','กรุงเทพ','patient','2025-08-30 07:15:17','2025-08-30 07:18:44'),('22b5e022-83bf-11f0-9b0d-00e04c688aa3','noppachai','$2b$10$W9BizVbyjVbYewPL3L6iw.VC7Ym4tN6M/6q7HSIVWn7ve4/.9MYAK','นพ. นพชัย ชัยพินิจ','noppachai@gmail.com','081-1234567','ศรีธัญญา','doctor','2025-08-28 03:28:59','2025-08-30 07:10:25'),('5e976d82-8564-11f0-9b0d-00e04c688aa3','nicha','$2b$10$/bgLGMQCH2hplNm.2V692OY/DBGMn99.hGMuqaeHsSIeCri/yOHGe','หมอนิชา อัศวเมธี','nicha@gmail.com','0987678961','รพ.ภูมิพล','doctor','2025-08-30 05:44:17','2025-08-30 06:53:00'),('60d2f3eb-83c4-11f0-9b0d-00e04c688aa3','Methaporn','$2b$10$X/dVrdq6Jc/DwpZXsD6Yg.OaAZQ0AxoM8apm7BpLGUmPKYbFNo2b2','นพ. เมธาพร ลิ้มรสธรรม','Methaporn@gmail.com','0976543218','Rmutto','doctor','2025-08-28 04:06:30','2025-08-30 06:28:17'),('b7a838cb-83bd-11f0-9b0d-00e04c688aa3','kittipob.jir','$2b$10$iXLXAJABu5TzPfdXXxwmMuZ0f7ZaiLJ2a1IzV1Pi0MUQwFfoRCqpm','Kittipob Jirapanichakul','','','','admin','2025-08-28 03:18:50','2025-08-30 06:41:10'),('c2f9445c-8571-11f0-9b0d-00e04c688aa3','kittipob','$2b$10$WfE8Rr5cGLwEIfmPf99wvecQBNILZXtFc.6VjKAUfSJu60RciELHy','นพ. กิตติภพ จิรพณิชกุล','kittipob@gmail.com','0879767651','รพ.บี แคร์','doctor','2025-08-30 07:20:09','2025-08-30 07:22:01'),('c8ce521e-82f8-11f0-9b0d-00e04c688aa3','Nutchaporn','$2b$10$OsalotER8i0oi3T4GQZX3.FuoOYuTvnAG6.yq7MhKuUKbPCscbwOu','ณัชพร พงศธรพิญโญ','nutchaporn@gmail.com','0975438656','ครัวแบมแบม1','patient','2025-08-27 03:49:08','2025-08-30 05:32:52');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping routines for database 'medicare'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-08-30 14:24:41
