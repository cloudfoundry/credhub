CREATE TABLE named_canary (
    id bigint NOT NULL,
    encrypted_value bytea,
    name character varying(255) NOT NULL,
    nonce bytea
);

ALTER TABLE ONLY named_canary
    ADD CONSTRAINT named_canary_pkey PRIMARY KEY (id);
