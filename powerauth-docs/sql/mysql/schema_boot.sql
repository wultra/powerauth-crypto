CREATE DATABASE `powerauth`;

CREATE USER 'powerauth'@'localhost';

GRANT ALL PRIVILEGES ON powerauth.* TO 'powerauth'@'localhost';

FLUSH PRIVILEGES;
