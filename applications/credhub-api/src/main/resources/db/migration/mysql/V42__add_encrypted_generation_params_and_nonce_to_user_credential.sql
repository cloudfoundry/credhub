ALTER TABLE user_credential
    ADD encrypted_generation_parameters blob,
    ADD parameters_nonce tinyblob;
