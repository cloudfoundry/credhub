CREATE TABLE rsa_secret (
    public_key character varying(7000),
    id bigint NOT NULL
);

ALTER TABLE ONLY rsa_secret
    ADD CONSTRAINT rsa_secret_pkey PRIMARY KEY (id);

ALTER TABLE ONLY rsa_secret
    ADD CONSTRAINT rsa_secret_fkey FOREIGN KEY (id) REFERENCES named_secret(id);
