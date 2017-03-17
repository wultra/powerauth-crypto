CREATE SCHEMA `powerauth` DEFAULT CHARACTER SET utf8 ;

CREATE USER 'powerauth'@'localhost';

GRANT ALL PRIVILEGES ON powerauth.* TO 'powerauth'@'localhost';

FLUSH PRIVILEGES;
