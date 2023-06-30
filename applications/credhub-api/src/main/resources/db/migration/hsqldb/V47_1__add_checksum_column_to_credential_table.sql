-- noinspection SqlDialectInspectionForFile

ALTER TABLE credential ADD checksum VARCHAR(100);

ALTER TABLE credential
  ADD CONSTRAINT checksum_unique UNIQUE(checksum);
