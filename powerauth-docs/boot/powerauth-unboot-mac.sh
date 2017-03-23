# Stop Tomcat Server
TOMCAT_VERSION=`ls /usr/local/Cellar/tomcat/`;
sh /usr/local/Cellar/tomcat/$TOMCAT_VERSION/bin/catalina stop;
sleep 10;

# Stop MySQL Service
brew services stop mysql;
sleep 2;

# Remove Homebrew Dependencies
brew remove --force mysql;
brew remove --force tomcat;
brew remove --force wget;
brew remove --force curl;

# Uninstall Homebrew
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/uninstall)";

# Drop MySQL Data
rm -rf /usr/local/var/mysql;
