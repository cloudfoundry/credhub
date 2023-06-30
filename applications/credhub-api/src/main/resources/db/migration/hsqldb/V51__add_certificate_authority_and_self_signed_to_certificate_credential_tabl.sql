ALTER TABLE certificate_credential
  ADD COLUMN certificate_authority BOOLEAN;

ALTER TABLE certificate_credential
    ADD COLUMN self_signed BOOLEAN;
