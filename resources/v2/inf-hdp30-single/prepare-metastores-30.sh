#!/usr/bin/env bash

# Intialize MetaStores

yum install -y https://download.postgresql.org/pub/repos/yum/9.6/redhat/rhel-7-x86_64/pgdg-redhat96-9.6-3.noarch.rpm
yum install -y postgresql96-server
yum install -y postgresql96-contrib
/usr/pgsql-9.6/bin/postgresql96-setup initdb
sed -i 's,#port = 5432,port = 5433,g' /var/lib/pgsql/9.6/data/postgresql.conf

echo '' >  /var/lib/pgsql/9.6/data/pg_hba.conf
echo 'local all das,streamsmsgmgr,cloudbreak,registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid           trust		' >> /var/lib/pgsql/9.6/data/pg_hba.conf
echo 'host  all das,streamsmsgmgr,cloudbreak,registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid 0.0.0.0/0 trust		' >> /var/lib/pgsql/9.6/data/pg_hba.conf
echo 'host  all das,streamsmsgmgr,cloudbreak,registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid ::/0      trust		' >> /var/lib/pgsql/9.6/data/pg_hba.conf
echo 'local all             all                                     									peer		' >> /var/lib/pgsql/9.6/data/pg_hba.conf
echo 'host  all             all             127.0.0.1/32            		 							ident		' >> /var/lib/pgsql/9.6/data/pg_hba.conf
echo 'host  all             all             ::1/128                 		 							ident		' >> /var/lib/pgsql/9.6/data/pg_hba.conf

systemctl enable postgresql-9.6.service
systemctl start postgresql-9.6.service

echo "CREATE DATABASE streamsmsgmgr;" | sudo -u postgres psql -U postgres -h localhost -p 5433
echo "CREATE USER streamsmsgmgr WITH PASSWORD 'streamsmsgmgr';" | sudo -u postgres psql -U postgres -h localhost -p 5433
echo "GRANT ALL PRIVILEGES ON DATABASE streamsmsgmgr TO streamsmsgmgr;" | sudo -u postgres psql -U postgres -h localhost -p 5433

echo "CREATE DATABASE druid;" | sudo -u postgres psql -U postgres
echo "CREATE DATABASE ranger;" | sudo -u postgres psql -U postgres
echo "CREATE DATABASE registry;" | sudo -u postgres psql -U postgres
echo "CREATE USER druid WITH PASSWORD 'druid';" | sudo -u postgres psql -U postgres
echo "CREATE USER registry WITH PASSWORD 'registry';" | sudo -u postgres psql -U postgres
echo "CREATE USER rangerdba WITH PASSWORD 'rangerdba';" | sudo -u postgres psql -U postgres
echo "CREATE USER rangeradmin WITH PASSWORD 'ranger';" | sudo -u postgres psql -U postgres
echo "GRANT ALL PRIVILEGES ON DATABASE druid TO druid;" | sudo -u postgres psql -U postgres
echo "GRANT ALL PRIVILEGES ON DATABASE registry TO registry;" | sudo -u postgres psql -U postgres
echo "GRANT ALL PRIVILEGES ON DATABASE ranger TO rangerdba;" | sudo -u postgres psql -U postgres
echo "GRANT ALL PRIVILEGES ON DATABASE ranger TO rangeradmin;" | sudo -u postgres psql -U postgres

#ambari-server setup --jdbc-db=postgres --jdbc-driver=/usr/share/java/postgresql-jdbc.jar

if [[ $(cat /etc/system-release|grep -Po Amazon) == "Amazon" ]]; then       		
	echo '' >  /var/lib/pgsql/9.5/data/pg_hba.conf
	echo 'local all cloudbreak,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,registry           trust		' >> /var/lib/pgsql/9.5/data/pg_hba.conf
	echo 'host  all cloudbreak,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,registry 0.0.0.0/0 trust		' >> /var/lib/pgsql/9.5/data/pg_hba.conf
	echo 'host  all cloudbreak,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,registry ::/0      trust		' >> /var/lib/pgsql/9.5/data/pg_hba.conf
	echo 'local all             all                                     				peer			' >> /var/lib/pgsql/9.5/data/pg_hba.conf
	echo 'host  all             all             127.0.0.1/32            		 		ident		' >> /var/lib/pgsql/9.5/data/pg_hba.conf
	echo 'host  all             all             ::1/128                 		 		ident		' >> /var/lib/pgsql/9.5/data/pg_hba.conf
	
	sudo -u postgres /usr/pgsql-9.5/bin/pg_ctl -D /var/lib/pgsql/9.5/data/ reload
else
	echo '' >  /var/lib/pgsql/data/pg_hba.conf
	echo 'local all cloudbreak,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,registry           trust		' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'host  all cloudbreak,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,registry 0.0.0.0/0 trust		' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'host  all cloudbreak,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,registry ::/0      trust		' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'local all             all                                     		 		peer			' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'host  all             all             127.0.0.1/32            		 		ident		' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'host  all             all             ::1/128                 		 		ident		' >> /var/lib/pgsql/data/pg_hba.conf
	
	sudo -u postgres pg_ctl -D /var/lib/pgsql/data/ reload
fi


yum remove -y mysql57-community*
yum remove -y mysql56-server*
yum remove -y mysql-community*
rm -Rvf /var/lib/mysql

yum install -y epel-release
yum install -y libffi-devel.x86_64
ln -s /usr/lib64/libffi.so.6 /usr/lib64/libffi.so.5

yum install -y mysql-connector-java*
ambari-server setup --jdbc-db=mysql --jdbc-driver=/usr/share/java/mysql-connector-java.jar

if [ $(cat /etc/system-release|grep -Po Amazon) == Amazon ]; then       	
	yum install -y mysql56-server
	service mysqld start
else
	yum localinstall -y https://dev.mysql.com/get/mysql-community-release-el7-5.noarch.rpm
	yum install -y mysql-community-server
	systemctl start mysqld.service
fi
chkconfig --add mysqld
chkconfig mysqld on

ln -s /usr/share/java/mysql-connector-java.jar /usr/hdp/current/hive-client/lib/mysql-connector-java.jar	
ln -s /usr/share/java/mysql-connector-java.jar /usr/hdp/current/hive-server2-hive2/lib/mysql-connector-java.jar

mysql --execute="CREATE DATABASE druid DEFAULT CHARACTER SET utf8"
mysql --execute="CREATE DATABASE registry DEFAULT CHARACTER SET utf8"
mysql --execute="CREATE DATABASE streamline DEFAULT CHARACTER SET utf8"
mysql --execute="CREATE DATABASE streamsmsgmgr DEFAULT CHARACTER SET utf8"
mysql --execute="CREATE USER 'das'@'localhost' IDENTIFIED BY 'dasuser'"
mysql --execute="CREATE USER 'das'@'%' IDENTIFIED BY 'dasuser'"
mysql --execute="CREATE USER 'ranger'@'localhost' IDENTIFIED BY 'ranger'"
mysql --execute="CREATE USER 'ranger'@'%' IDENTIFIED BY 'ranger'"
mysql --execute="CREATE USER 'rangerdba'@'localhost' IDENTIFIED BY 'rangerdba'"
mysql --execute="CREATE USER 'rangerdba'@'%' IDENTIFIED BY 'rangerdba'"
mysql --execute="CREATE USER 'registry'@'localhost' IDENTIFIED BY 'registry'"
mysql --execute="CREATE USER 'registry'@'%' IDENTIFIED BY 'registry'"
mysql --execute="CREATE USER 'streamsmsgmgr'@'localhost' IDENTIFIED BY 'streamsmsgmgr'"
mysql --execute="CREATE USER 'streamsmsgmgr'@'%' IDENTIFIED BY 'streamsmsgmgr'"
mysql --execute="CREATE USER 'druid'@'%' IDENTIFIED BY 'druid'"
mysql --execute="CREATE USER 'streamline'@'%' IDENTIFIED BY 'streamline'"
mysql --execute="CREATE USER 'streamline'@'localhost' IDENTIFIED BY 'streamline'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'das'@'localhost'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'das'@'%'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'das'@'localhost' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'das'@'%' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'ranger'@'localhost'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'ranger'@'%'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'ranger'@'localhost' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'ranger'@'%' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'rangerdba'@'localhost'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'rangerdba'@'%'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'rangerdba'@'localhost' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'rangerdba'@'%' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON druid.* TO 'druid'@'%' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'registry'@'localhost'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'registry'@'%'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'registry'@'localhost' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'registry'@'%' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'streamsmsgmgr'@'localhost'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'streamsmsgmgr'@'%'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'streamsmsgmgr'@'localhost' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'streamsmsgmgr'@'%' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON streamline.* TO 'streamline'@'%' WITH GRANT OPTION"
mysql --execute="FLUSH PRIVILEGES"
mysql --execute="COMMIT"
