CREATE TABLE user_secret (
    uuid uuid NOT NULL PRIMARY KEY,
    username character varying(7000),
    FOREIGN KEY(uuid)
      REFERENCES named_secret(uuid)
      ON DELETE CASCADE
);
