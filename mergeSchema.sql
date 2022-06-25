CREATE ROLE ios LOGIN Password '123456';

DROP TYPE IF EXISTS PhoneType CASCADE;
CREATE TYPE PhoneType AS ENUM ('iphone','android');

DROP TABLE IF EXISTS Collections CASCADE;
CREATE TABLE Collections (
    id                  SERIAL PRIMARY KEY,
    phone               PhoneType,
    start_time          timestamp,
    end_time            timestamp
);

DROP TABLE IF EXISTS Apps CASCADE;
CREATE TABLE Apps (
    name           varchar,
    version        varchar,
    PRIMARY KEY (name, version)
);


DROP TABLE IF EXISTS AppMonitorings CASCADE;
CREATE TABLE AppMonitorings (
    id                      SERIAL PRIMARY KEY,
    collection              int,
    app_name                varchar,
    app_version             varchar,
    error                   varchar,
    FOREIGN KEY (collection)
    REFERENCES Collections(id)
    ON DELETE CASCADE,
    FOREIGN KEY (app_name, app_version)
    REFERENCES Apps(name, version)
    ON DELETE CASCADE
);

DROP TABLE IF EXISTS Requests CASCADE;
CREATE TABLE Requests (
    id              SERIAL PRIMARY KEY,
    monitoring_id   int,
    start_time      timestamp,
    scheme          varchar,
    method          varchar,
    host            varchar,
    port            varchar,
    path            varchar,
    content         varchar,
    authority       varchar,
    http_version    varchar,
    FOREIGN KEY (monitoring_id)
    REFERENCES AppMonitorings(id)
    ON DELETE CASCADE
);

DROP TABLE IF EXISTS Cookies CASCADE;
CREATE TABLE Cookies(
    id              SERIAL PRIMARY KEY,
    request         int,
    name            varchar,
    values          varchar,
    FOREIGN KEY (request)
    REFERENCES Requests(id)
);

DROP TABLE IF EXISTS Headers CASCADE;
CREATE TABLE Headers(
    id              SERIAL PRIMARY KEY,
    request         int,
    name            varchar,
    values          varchar,
    FOREIGN KEY (request)
    REFERENCES Requests(id)
);

GRANT SELECT, INSERT, UPDATE ON Collections, Apps, Requests, Cookies, Headers, AppMonitorings
TO ios;

GRANT USAGE ON collections_id_seq, requests_id_seq, cookies_id_seq, headers_id_seq, appmonitorings_id_seq TO ios;
