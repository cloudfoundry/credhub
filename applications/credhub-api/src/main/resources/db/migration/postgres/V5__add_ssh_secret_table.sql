CREATE TABLE ssh_secret (
    public_key character varying(7000),
    id bigint NOT NULL
);

ALTER TABLE ONLY ssh_secret
    ADD CONSTRAINT ssh_secret_pkey PRIMARY KEY (id);

ALTER TABLE ONLY ssh_secret
    ADD CONSTRAINT ssh_secret_fkey FOREIGN KEY (id) REFERENCES named_secret(id);