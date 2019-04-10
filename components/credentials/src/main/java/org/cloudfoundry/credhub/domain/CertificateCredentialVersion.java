package org.cloudfoundry.credhub.domain;

import java.time.Instant;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.requests.GenerationParameters;
import org.cloudfoundry.credhub.utils.CertificateReader;

public class CertificateCredentialVersion extends CredentialVersion {

  private final CertificateCredentialVersionData delegate;
  private CertificateReader parsedCertificate;

  public CertificateCredentialVersion(final CertificateCredentialVersionData delegate) {
    super(delegate);
    this.delegate = delegate;
    this.setCertificate(delegate.getCertificate());
  }

  public CertificateCredentialVersion(final String name) {
    this(new CertificateCredentialVersionData(name));
  }

  public CertificateCredentialVersion() {
    this(new CertificateCredentialVersionData());
  }

  public CertificateCredentialVersion(final CertificateCredentialValue certificate, final Encryptor encryptor) {
    this();
    this.setEncryptor(encryptor);
    this.setCa(certificate.getCa());
    this.setPrivateKey(certificate.getPrivateKey());
    this.setCaName(certificate.getCaName());
    this.setCertificate(certificate.getCertificate());
    this.setTransitional(certificate.isTransitional());
    this.setExpiryDate(certificate.getExpiryDate());
  }

  public CertificateReader getParsedCertificate() {
    return this.parsedCertificate;
  }

  public String getCa() {
    return delegate.getCa();
  }

  public void setCa(final String ca) {
    delegate.setCa(ca);
  }

  public String getCertificate() {
    return delegate.getCertificate();
  }

  public void setCertificate(final String certificate) {
    delegate.setCertificate(certificate);
    if (StringUtils.isNotEmpty(delegate.getCertificate())) {
      parsedCertificate = new CertificateReader(certificate);
    }
  }

  public String getPrivateKey() {
    return (String) super.getValue();
  }

  public void setPrivateKey(final String privateKey) {
    if (privateKey != null) {
      super.setValue(privateKey);
    }
  }

  public String getCaName() {
    return delegate.getCaName();
  }

  public void setCaName(final String caName) {
    delegate.setCaName(caName);
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }

  @Override
  public void rotate() {
    final String decryptedPrivateKey = this.getPrivateKey();
    this.setPrivateKey(decryptedPrivateKey);
  }

  @Override
  public boolean matchesGenerationParameters(final GenerationParameters generationParameters) {
    if (generationParameters == null) {
      return true;
    }

    final CertificateGenerationParameters parameters = (CertificateGenerationParameters) generationParameters;
    final CertificateGenerationParameters existingGenerationParameters = new CertificateGenerationParameters(getParsedCertificate(), getCaName());
    return existingGenerationParameters.equals(parameters);
  }

  public void setTransitional(final boolean transitional) {
    delegate.setTransitional(transitional);
  }

  public Instant getExpiryDate() {
    return delegate.getExpiryDate();
  }

  public void setExpiryDate(final Instant expiryDate) {
    delegate.setExpiryDate(expiryDate);
  }

  public boolean isVersionTransitional() {
    return delegate.isTransitional();
  }

  @Override
  public GenerationParameters getGenerationParameters() {
    return null;
  }
}
