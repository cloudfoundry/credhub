ALTER TABLE user_credential
  ADD encrypted_generation_parameters BINARY(271);
ALTER TABLE user_credential
  ADD parameters_nonce BINARY(16);
