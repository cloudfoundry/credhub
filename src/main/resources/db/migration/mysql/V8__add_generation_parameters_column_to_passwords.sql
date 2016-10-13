ALTER TABLE password_secret
    ADD encrypted_generation_parameters blob,
    ADD parameters_nonce tinyblob;
