#!/usr/bin/env bash


#Configure public hostname for Ambari
sed -i 's/\[agent\]/\[agent\]\npublic_hostname_script=\/var\/lib\/ambari-agent\/public_hostname.sh/' /etc/ambari-agent/conf/ambari-agent.ini
cat > /var/lib/ambari-agent/public_hostname.sh << EOF
#!/bin/sh
echo "'""$(curl https://icanhazptr.com)""'"
EOF
chmod +x /var/lib/ambari-agent/public_hostname.sh

########### Initialize Metadata Stores #################

#Install Postgres 9.6
if [[ $(cat /etc/system-release|grep -Po Amazon) == "Amazon" ]]; then
	yum install -y https://download.postgresql.org/pub/repos/yum/9.6/redhat/rhel-6-x86_64/pgdg-ami201503-96-9.6-2.noarch.rpm
	yum install -y postgresql96-server postgresql96-contrib
	service postgresql-9.6 initdb

	echo '' >  /var/lib/pgsql/9.5/data/pg_hba.conf
	echo 'local all das,streamsmsgmgr,cloudbreak,registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,registry           trust		' >> /var/lib/pgsql/9.6/data/pg_hba.conf
	echo 'host  all das,streamsmsgmgr,cloudbreak,registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,registry 0.0.0.0/0 trust		' >> /var/lib/pgsql/9.6/data/pg_hba.conf
	echo 'host  all das,streamsmsgmgr,cloudbreak,registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,registry ::/0      trust		' >> /var/lib/pgsql/9.6/data/pg_hba.conf
	echo 'local all             all                                     									peer			' >> /var/lib/pgsql/9.6/data/pg_hba.conf
	echo 'host  all             all             127.0.0.1/32            		 							trust		' >> /var/lib/pgsql/9.6/data/pg_hba.conf
	echo 'host  all             all             ::1/128                 		 							ident		' >> /var/lib/pgsql/9.6/data/pg_hba.conf

	sudo -u postgres /usr/pgsql-9.5/bin/pg_ctl -D /var/lib/pgsql/9.5/data/ reload
else
	yum install -y https://download.postgresql.org/pub/repos/yum/9.6/redhat/rhel-7-x86_64/pgdg-redhat96-9.6-3.noarch.rpm
	yum install -y postgresql96-server postgresql96-contrib
	/usr/pgsql-9.6/bin/postgresql96-setup initdb

	echo '' >  /var/lib/pgsql/data/pg_hba.conf
	echo 'local all das,streamsmsgmgr,cloudbreak,registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,registry           trust		' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'host  all das,streamsmsgmgr,cloudbreak,registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,registry 0.0.0.0/0 trust		' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'host  all das,streamsmsgmgr,cloudbreak,registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,registry ::/0      trust		' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'local all             all                                     									peer			' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'host  all             all             127.0.0.1/32            		 							trust		' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'host  all             all             ::1/128													ident		' >> /var/lib/pgsql/data/pg_hba.conf

	sudo -u postgres pg_ctl -D /var/lib/pgsql/data/ reload
fi

#Set Postgres 9.6 listen port to 5433 to avoid collision with default Postgres instance
sed -i 's,#port = 5432,port = 5433,g' /var/lib/pgsql/9.6/data/postgresql.conf

#Configure Postgres 9.6 ACL
echo '' >  /var/lib/pgsql/9.6/data/pg_hba.conf
echo 'local all das,streamsmsgmgr,cloudbreak,registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,registry           trust		' >> /var/lib/pgsql/9.6/data/pg_hba.conf
echo 'host  all das,streamsmsgmgr,cloudbreak,registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,registry 0.0.0.0/0 trust		' >> /var/lib/pgsql/9.6/data/pg_hba.conf
echo 'host  all das,streamsmsgmgr,cloudbreak,registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,registry ::/0      trust		' >> /var/lib/pgsql/9.6/data/pg_hba.conf
echo 'local all             all                                     									peer			' >> /var/lib/pgsql/9.6/data/pg_hba.conf
echo 'host  all             all             127.0.0.1/32            		 							trust		' >> /var/lib/pgsql/9.6/data/pg_hba.conf
echo 'host  all             all             ::1/128                 		 							ident		' >> /var/lib/pgsql/9.6/data/pg_hba.conf

systemctl enable postgresql-9.6.service
systemctl start postgresql-9.6.service

echo "CREATE DATABASE das;" | sudo -u postgres psql -U postgres -h localhost -p 5433

echo "CREATE DATABASE streamsmsgmgr;" | sudo -u postgres psql -U postgres -h localhost -p 5433
echo "CREATE USER streamsmsgmgr WITH PASSWORD 'streamsmsgmgr';" | sudo -u postgres psql -U postgres -h localhost -p 5433
echo "GRANT ALL PRIVILEGES ON DATABASE streamsmsgmgr TO streamsmsgmgr;" | sudo -u postgres psql -U postgres -h localhost -p 5433

echo "CREATE DATABASE registry;" | sudo -u postgres psql -U postgres -h localhost -p 5433
echo "CREATE USER registry WITH PASSWORD 'registry';" | sudo -u postgres psql -U postgres -h localhost -p 5433
echo "GRANT ALL PRIVILEGES ON DATABASE registry TO registry;" | sudo -u postgres psql -U postgres -h localhost -p 5433

echo "CREATE DATABASE druid;" | sudo -u postgres psql -U postgres
echo "CREATE USER druid WITH PASSWORD 'druid';" | sudo -u postgres psql -U postgres
echo "GRANT ALL PRIVILEGES ON DATABASE druid TO druid;" | sudo -u postgres psql -U postgres

#echo "CREATE DATABASE ranger;" | sudo -u postgres psql -U postgres
#echo "CREATE USER rangerdba WITH PASSWORD 'rangerdba';" | sudo -u postgres psql -U postgres
#echo "CREATE USER rangeradmin WITH PASSWORD 'ranger';" | sudo -u postgres psql -U postgres

#echo "GRANT ALL PRIVILEGES ON DATABASE ranger TO rangerdba;" | sudo -u postgres psql -U postgres
#echo "GRANT ALL PRIVILEGES ON DATABASE ranger TO rangeradmin;" | sudo -u postgres psql -U postgres

#Install MySQL
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
	yum localinstall -y https://dev.mysql.com/get/mysql57-community-release-el7-11.noarch.rpm
else
	yum localinstall -y https://dev.mysql.com/get/mysql-community-release-el7-5.noarch.rpm
fi
yum install -y mysql-community-server
echo "validate_password_policy=LOW" >> /etc/my.cnf
systemctl start mysqld.service
chkconfig --add mysqld
chkconfig mysqld on

ln -s /usr/share/java/mysql-connector-java.jar /usr/hdp/current/hive-client/lib/mysql-connector-java.jar
ln -s /usr/share/java/mysql-connector-java.jar /usr/hdp/current/hive-server2-hive2/lib/mysql-connector-java.jar

mysql --execute="CREATE DATABASE registry DEFAULT CHARACTER SET utf8"
mysql --execute="CREATE DATABASE streamline DEFAULT CHARACTER SET utf8"
mysql --execute="CREATE DATABASE streamsmsgmgr DEFAULT CHARACTER SET utf8"
mysql --execute="CREATE USER 'registry'@'localhost' IDENTIFIED BY 'registry'"
mysql --execute="CREATE USER 'registry'@'%' IDENTIFIED BY 'registry'"
mysql --execute="CREATE USER 'streamsmsgmgr'@'localhost' IDENTIFIED BY 'streamsmsgmgr'"
mysql --execute="CREATE USER 'streamsmsgmgr'@'%' IDENTIFIED BY 'streamsmsgmgr'"
mysql --execute="CREATE USER 'streamline'@'%' IDENTIFIED BY 'streamline'"
mysql --execute="CREATE USER 'streamline'@'localhost' IDENTIFIED BY 'streamline'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'registry'@'localhost'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'registry'@'%'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'registry'@'localhost' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'registry'@'%' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'streamsmsgmgr'@'localhost'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'streamsmsgmgr'@'%'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'streamsmsgmgr'@'localhost' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'streamsmsgmgr'@'%' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'streamline'@'localhost'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'streamline'@'%'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'streamline'@'localhost' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON streamline.* TO 'streamline'@'%' WITH GRANT OPTION"
mysql --execute="CREATE USER 'efm'@'%' IDENTIFIED BY 'efm'"
mysql --execute="CREATE USER 'efm'@'localhost' IDENTIFIED BY 'efm'"
mysql --execute="CREATE DATABASE efm DEFAULT CHARACTER SET utf8"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'efm'@'localhost'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'efm'@'%'"
mysql --execute="GRANT ALL PRIVILEGES ON *.* TO 'efm'@'localhost' WITH GRANT OPTION"
mysql --execute="GRANT ALL PRIVILEGES ON efm.* TO 'efm'@'%' WITH GRANT OPTION"
mysql --execute="FLUSH PRIVILEGES"
mysql --execute="COMMIT"