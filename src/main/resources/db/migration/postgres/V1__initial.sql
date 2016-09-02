--
-- PostgreSQL database dump
--

-- Dumped from database version 9.5.2
-- Dumped by pg_dump version 9.5.2

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner:
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET search_path = public, pg_catalog;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: auth_failure_audit_record; Type: TABLE; Schema: public; Owner: pivotal
--

CREATE TABLE auth_failure_audit_record (
    id bigint NOT NULL,
    failure_description character varying(2000),
    host_name character varying(255),
    now timestamp without time zone,
    operation character varying(255),
    path character varying(255),
    requester_ip character varying(255),
    token_expires bigint NOT NULL,
    token_issued bigint NOT NULL,
    uaa_url character varying(255),
    user_id character varying(255),
    user_name character varying(255),
    x_forwarded_for character varying(255)
);

--
-- Name: certificate_secret; Type: TABLE; Schema: public; Owner: pivotal
--

CREATE TABLE certificate_secret (
    ca character varying(7000),
    certificate character varying(7000),
    id bigint NOT NULL
);

--
-- Name: hibernate_sequence; Type: SEQUENCE; Schema: public; Owner: pivotal
--

CREATE SEQUENCE hibernate_sequence
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: named_certificate_authority; Type: TABLE; Schema: public; Owner: pivotal
--

CREATE TABLE named_certificate_authority (
    id bigint NOT NULL,
    certificate character varying(7000),
    encrypted_value bytea,
    name character varying(255) NOT NULL,
    nonce bytea,
    type character varying(255),
    updated_at bigint NOT NULL
);

--
-- Name: named_secret; Type: TABLE; Schema: public; Owner: pivotal
--

CREATE TABLE named_secret (
    type character varying(31) NOT NULL,
    id bigint NOT NULL,
    encrypted_value bytea,
    name character varying(255) NOT NULL,
    nonce bytea,
    updated_at bigint NOT NULL,
    uuid character varying(255)
);

--
-- Name: operation_audit_record; Type: TABLE; Schema: public; Owner: pivotal
--

CREATE TABLE operation_audit_record (
    id bigint NOT NULL,
    host_name character varying(255),
    now bigint NOT NULL,
    operation character varying(255),
    path character varying(255),
    requester_ip character varying(255),
    success boolean NOT NULL,
    token_expires bigint NOT NULL,
    token_issued bigint NOT NULL,
    uaa_url character varying(255),
    user_id character varying(255),
    user_name character varying(255),
    x_forwarded_for character varying(255)
);

--
-- Name: password_secret; Type: TABLE; Schema: public; Owner: pivotal
--

CREATE TABLE password_secret (
    id bigint NOT NULL
);

--
-- Name: value_secret; Type: TABLE; Schema: public; Owner: pivotal
--

CREATE TABLE value_secret (
    id bigint NOT NULL
);

--
-- Name: auth_failure_audit_record_pkey; Type: CONSTRAINT; Schema: public; Owner: pivotal
--

ALTER TABLE ONLY auth_failure_audit_record
    ADD CONSTRAINT auth_failure_audit_record_pkey PRIMARY KEY (id);


--
-- Name: certificate_secret_pkey; Type: CONSTRAINT; Schema: public; Owner: pivotal
--

ALTER TABLE ONLY certificate_secret
    ADD CONSTRAINT certificate_secret_pkey PRIMARY KEY (id);


--
-- Name: named_certificate_authority_pkey; Type: CONSTRAINT; Schema: public; Owner: pivotal
--

ALTER TABLE ONLY named_certificate_authority
    ADD CONSTRAINT named_certificate_authority_pkey PRIMARY KEY (id);


--
-- Name: named_secret_pkey; Type: CONSTRAINT; Schema: public; Owner: pivotal
--

ALTER TABLE ONLY named_secret
    ADD CONSTRAINT named_secret_pkey PRIMARY KEY (id);


--
-- Name: operation_audit_record_pkey; Type: CONSTRAINT; Schema: public; Owner: pivotal
--

ALTER TABLE ONLY operation_audit_record
    ADD CONSTRAINT operation_audit_record_pkey PRIMARY KEY (id);


--
-- Name: password_secret_pkey; Type: CONSTRAINT; Schema: public; Owner: pivotal
--

ALTER TABLE ONLY password_secret
    ADD CONSTRAINT password_secret_pkey PRIMARY KEY (id);


--
-- Name: uk_5ic6w4fi93q8y7xv7280yhsmr; Type: CONSTRAINT; Schema: public; Owner: pivotal
--

ALTER TABLE ONLY named_certificate_authority
    ADD CONSTRAINT uk_5ic6w4fi93q8y7xv7280yhsmr UNIQUE (name);


--
-- Name: uk_iv5vf8iqm1sd3k3nacbm20ixp; Type: CONSTRAINT; Schema: public; Owner: pivotal
--

ALTER TABLE ONLY named_secret
    ADD CONSTRAINT uk_iv5vf8iqm1sd3k3nacbm20ixp UNIQUE (name);


--
-- Name: value_secret_pkey; Type: CONSTRAINT; Schema: public; Owner: pivotal
--

ALTER TABLE ONLY value_secret
    ADD CONSTRAINT value_secret_pkey PRIMARY KEY (id);


--
-- Name: fk31hqe03pkugu8u5ng564ko2nv; Type: FK CONSTRAINT; Schema: public; Owner: pivotal
--

ALTER TABLE ONLY password_secret
    ADD CONSTRAINT fk31hqe03pkugu8u5ng564ko2nv FOREIGN KEY (id) REFERENCES named_secret(id);


--
-- Name: fk34brqrqsrtkaf3gmty1rjkyjd; Type: FK CONSTRAINT; Schema: public; Owner: pivotal
--

ALTER TABLE ONLY certificate_secret
    ADD CONSTRAINT fk34brqrqsrtkaf3gmty1rjkyjd FOREIGN KEY (id) REFERENCES named_secret(id);


--
-- Name: fkox93sy15f6pgbdr89kp05pnfq; Type: FK CONSTRAINT; Schema: public; Owner: pivotal
--

ALTER TABLE ONLY value_secret
    ADD CONSTRAINT fkox93sy15f6pgbdr89kp05pnfq FOREIGN KEY (id) REFERENCES named_secret(id);

--
-- PostgreSQL database dump complete
--

