package io.pivotal.security.generator;

import io.pivotal.security.model.CertificateSecret;
import io.pivotal.security.model.CertificateSecretParameters;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

public interface CertificateGenerator {
  CertificateSecret generateCertificate(CertificateSecretParameters params) throws NoSuchProviderException, NoSuchAlgorithmException, CertificateException, InvalidKeyException, SignatureException, IOException;
}
