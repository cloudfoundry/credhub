ALTER TABLE credential ADD COLUMN checksum VARCHAR(100);

ALTER TABLE credential ADD CONSTRAINT unique_checksum UNIQUE (checksum);
