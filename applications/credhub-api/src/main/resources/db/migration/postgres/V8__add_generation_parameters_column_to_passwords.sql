ALTER TABLE password_secret
    ADD encrypted_generation_parameters bytea,
    ADD parameters_nonce bytea;
