CREATE DATABASE `powerauth`;

CREATE USER 'powerauth'@'%';

GRANT ALL PRIVILEGES ON powerauth.* TO 'powerauth'@'%';

FLUSH PRIVILEGES;

USE powerauth;
