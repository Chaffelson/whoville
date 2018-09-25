#!/bin/bash

#remount tmpfs to ensure NOEXEC is disabled
mount -o remount,size=10G /tmp
mount -o remount,exec /tmp

download_mysql_jdbc_driver() {
  yum install -y mysql-connector-java
}

main() {
  download_mysql_jdbc_driver
}

main