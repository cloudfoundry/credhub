package io.pivotal.security.generator;

import io.pivotal.security.model.CertificateSecret;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

public interface CertificateGenerator {
  CertificateSecret generateCertificate() throws NoSuchProviderException, NoSuchAlgorithmException, CertificateException, InvalidKeyException, SignatureException;
}
