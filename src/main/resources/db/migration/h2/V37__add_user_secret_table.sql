CREATE CACHED TABLE user_secret (
    uuid BINARY(16) NOT NULL PRIMARY KEY,
    username VARCHAR(7000),
    FOREIGN KEY (uuid)
      REFERENCES named_secret(uuid)
      ON DELETE CASCADE
      NOCHECK
);
