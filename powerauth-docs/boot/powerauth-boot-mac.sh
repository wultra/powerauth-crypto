# Install Homebrew
clear
while true; do
    read -p "Do you wish to (re)install Homebrew? [y/n] " yn
    case $yn in
        [Yy]* )
            /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
            brew update;
            brew upgrade;
            break
            ;;
        [Nn]* )
            break
            ;;
        * ) echo "Please answer yes or no.";;
    esac
done

# Install Technical Pre-requisites
clear
while true; do
    read -p "Do you wish to (re)install cURL? [y/n] " yn
    case $yn in
        [Yy]* )
            brew install curl
            break
            ;;
        [Nn]* )
            break
            ;;
        * ) echo "Please answer yes or no.";;
    esac
done

clear
while true; do
    read -p "Do you wish to (re)install wget? [y/n] " yn
    case $yn in
        [Yy]* )
            brew install wget
            break
            ;;
        [Nn]* )
            break
            ;;
        * ) echo "Please answer yes or no.";;
    esac
done

# Install MySQL And Start Service
clear
while true; do
    read -p "Do you wish to (re)install MySQL and launch it? [y/n] " yn
    case $yn in
        [Yy]* )
            brew install mysql
            brew services start mysql
            sleep 2
            break
            ;;
        [Nn]* )
            break
            ;;
        * ) echo "Please answer yes or no.";;
    esac
done

# Download SQL Scripts
clear
while true; do
    read -p "Do you wish to create MySQL schema for PowerAuth database? [y/n] " yn
    case $yn in
        [Yy]* )
            curl https://raw.githubusercontent.com/lime-company/lime-security-powerauth/master/powerauth-docs/sql/mysql/schema_boot.sql > /tmp/schema_boot.sql;
            printf "USE powerauth;\r\r" > /tmp/create_schema.sql;
            curl https://raw.githubusercontent.com/lime-company/lime-security-powerauth/master/powerauth-docs/sql/mysql/create_schema.sql >> /tmp/create_schema.sql;

            # Execute scripts
            mysql -u root < /tmp/schema_boot.sql;
            mysql -u root < /tmp/create_schema.sql;
            break
            ;;
        [Nn]* )
            break
            ;;
        * ) echo "Please answer yes or no.";;
    esac
done

# Install Tomcat Server
clear
while true; do
    read -p "Do you wish to (re)install Tomcat and launch it? [y/n] " yn
    case $yn in
        [Yy]* )
            brew install tomcat;
            TOMCAT_VERSION=`ls /usr/local/Cellar/tomcat/`;

            # Prepare Tomcat Libraries
            wget http://central.maven.org/maven2/mysql/mysql-connector-java/5.1.41/mysql-connector-java-5.1.41.jar -O "/usr/local/Cellar/tomcat/$TOMCAT_VERSION/libexec/lib/mysql-connector-java.jar";

            # Start Tomcat Server
            sh "/usr/local/Cellar/tomcat/$TOMCAT_VERSION/bin/catalina" start;
            sleep 5
            until [ "`curl --silent --connect-timeout 1 http://localhost:8080 | grep 'Apache Tomcat'`" != "" ];
            do
              sleep 10
            done
            break
            ;;
        [Nn]* )
            break
            ;;
        * ) echo "Please answer yes or no.";;
    esac
done

# Download PowerAuth 2.0 Server WAR
clear
while true; do
    read -p "Do you wish to deploy PowerAuth Server and PowerAuth Admin? [y/n] " yn
    case $yn in
        [Yy]* )
            wget https://github.com/lime-company/lime-security-powerauth/releases/download/0.14.0/powerauth-java-server.war -O "/tmp/powerauth-java-server.war";
            wget https://github.com/lime-company/lime-security-powerauth-admin/releases/download/0.14.0/powerauth-admin.war -O "/tmp/powerauth-admin.war";

            cp "/tmp/powerauth-java-server.war" "/usr/local/Cellar/tomcat/$TOMCAT_VERSION/libexec/webapps/powerauth-java-server.war";
            cp "/tmp/powerauth-admin.war" "/usr/local/Cellar/tomcat/$TOMCAT_VERSION/libexec/webapps/powerauth-admin.war";
            until [ "`curl --silent --connect-timeout 1 http://localhost:8080/powerauth-admin/application/list | grep 'PowerAuth'`" != "" ];
            do
              sleep 10
            done

            # Open PowerAuth 2.0 Software
            open http://localhost:8080/powerauth-java-server/soap/service.wsdl;
            open http://localhost:8080/powerauth-admin;
            break
            ;;
        [Nn]* )
            break
            ;;
        * ) echo "Please answer yes or no.";;
    esac
done
