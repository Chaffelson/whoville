CREATE TABLE IF NOT EXISTS timesheet (
 driverid BIGINT NOT NULL,
 week BIGINT NOT NULL,
 hours_logged BIGINT,
 miles_logged BIGINT,
 CONSTRAINT pk PRIMARY KEY (driverid,week));
CREATE TABLE IF NOT EXISTS drivers (
 driverid BIGINT NOT NULL,
 name VARCHAR(50),
 certified CHAR(1),
 wage_plan VARCHAR(50),
 CONSTRAINT pk PRIMARY KEY (driverid));
