ALTER TABLE user_credential
    ADD encrypted_generation_parameters bytea,
    ADD parameters_nonce bytea;
