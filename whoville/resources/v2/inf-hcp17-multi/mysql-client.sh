#!/bin/bash

download_mysql_jdbc_driver() {
  yum install -y mysql-connector-java
}

main() {
  download_mysql_jdbc_driver
}

main