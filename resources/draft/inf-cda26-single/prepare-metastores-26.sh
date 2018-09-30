#!/bin/bash

#configure metastore users and permissions on local ambari database
echo "CREATE DATABASE druid;" | sudo -Hiu postgres psql -U postgres
echo "CREATE DATABASE streamline;" | sudo -Hiu postgres psql -U postgres
echo "CREATE DATABASE druid;" | sudo -Hiu postgres psql -U postgres
echo "CREATE DATABASE ranger;" | sudo -Hiu postgres psql -U postgres
echo "CREATE DATABASE registry;" | sudo -Hiu postgres psql -U postgres
echo "CREATE USER druid WITH PASSWORD 'druid';" | sudo -Hiu postgres psql -U postgres
echo "CREATE USER streamline WITH PASSWORD 'streamline';" | sudo -Hiu postgres psql -U postgres
echo "CREATE USER ranger WITH PASSWORD 'ranger';" | sudo -Hiu postgres psql -U postgres
echo "CREATE USER registry WITH PASSWORD 'registry';" | sudo -Hiu postgres psql -U postgres
echo "CREATE USER rangerdba WITH PASSWORD 'rangerdba';" | sudo -Hiu postgres psql -U postgres
echo "CREATE USER rangeradmin WITH PASSWORD 'ranger'" | sudo -Hiu postgres psql -U postgres
echo "GRANT ALL PRIVILEGES ON DATABASE druid TO druid;" | sudo -Hiu postgres psql -U postgres
echo "GRANT ALL PRIVILEGES ON DATABASE streamline TO streamline;" | sudo -Hiu postgres psql -U postgres
echo "GRANT ALL PRIVILEGES ON DATABASE registry TO registry;" | sudo -Hiu postgres psql -U postgres
echo "GRANT ALL PRIVILEGES ON DATABASE ranger TO rangerdba;" | sudo -Hiu postgres psql -U postgres
echo "GRANT ALL PRIVILEGES ON DATABASE ranger TO ranger;" | sudo -Hiu postgres psql -U postgres

#ambari-server setup --jdbc-db=postgres --jdbc-driver=/usr/share/java/postgresql-jdbc.jar

export HADOOP_CLASSPATH=${HADOOP_CLASSPATH}:${JAVA_JDBC_LIBS}:/connector jar path

if [[ $(cat /etc/system-release|grep -Po Amazon) == "Amazon" ]]; then       		
	echo '' >  /var/lib/pgsql/9.5/data/pg_hba.conf
	#echo 'host  ambari ambari 									    0.0.0.0/0 		md5			' >> /var/lib/pgsql/9.5/data/pg_hba.conf
	#echo 'local ambari ambari 									              		md5			' >> /var/lib/pgsql/9.5/data/pg_hba.conf
	echo 'local all registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,streamline           trust		' >> /var/lib/pgsql/9.5/data/pg_hba.conf
	echo 'host  all registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,streamline 0.0.0.0/0 trust		' >> /var/lib/pgsql/9.5/data/pg_hba.conf
	echo 'host  all registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,streamline ::/0      trust		' >> /var/lib/pgsql/9.5/data/pg_hba.conf
	echo 'local all             all                                     				peer			' >> /var/lib/pgsql/9.5/data/pg_hba.conf
	echo 'host  all             all             127.0.0.1/32            		 		ident		' >> /var/lib/pgsql/9.5/data/pg_hba.conf
	echo 'host  all             all             ::1/128                 		 		ident		' >> /var/lib/pgsql/9.5/data/pg_hba.conf
	
	sudo -Hiu postgres /usr/pgsql-9.5/bin/pg_ctl -D /var/lib/pgsql/9.5/data/ reload
else
	echo '' >  /var/lib/pgsql/data/pg_hba.conf
	#echo 'host  ambari ambari 									    0.0.0.0/0 		md5			' >> /var/lib/pgsql/data/pg_hba.conf
	#echo 'local ambari ambari 									              		md5			' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'local all registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,streamline           trust		' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'host  all registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,streamline 0.0.0.0/0 trust		' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'host  all registry,ambari,postgres,hive,ranger,rangerdba,rangeradmin,rangerlogger,druid,streamline ::/0      trust		' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'local all             all                                     		 		peer			' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'host  all             all             127.0.0.1/32            		 		ident		' >> /var/lib/pgsql/data/pg_hba.conf
	echo 'host  all             all             ::1/128                 		 		ident		' >> /var/lib/pgsql/data/pg_hba.conf
	
	sudo -Hiu postgres pg_ctl -D /var/lib/pgsql/data/ reload
fi

exit 0