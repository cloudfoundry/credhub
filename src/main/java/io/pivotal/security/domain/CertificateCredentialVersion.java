package io.pivotal.security.domain;

import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.entity.CertificateCredentialVersionData;
import io.pivotal.security.request.GenerationParameters;
import io.pivotal.security.util.CertificateReader;
import org.apache.commons.lang3.StringUtils;

public class CertificateCredentialVersion extends CredentialVersion<CertificateCredentialVersion> {

  private CertificateCredentialVersionData delegate;
  private CertificateReader parsedCertificate;

  public CertificateCredentialVersion(CertificateCredentialVersionData delegate) {
    super(delegate);
    this.delegate = delegate;
    this.setCertificate(delegate.getCertificate());
  }

  public CertificateCredentialVersion(String name) {
    this(new CertificateCredentialVersionData(name));
  }

  public CertificateCredentialVersion() {
    this(new CertificateCredentialVersionData());
  }

  public CertificateCredentialVersion(CertificateCredentialValue certificate, Encryptor encryptor) {
    this();
    this.setEncryptor(encryptor);
    this.setCa(certificate.getCa());
    this.setPrivateKey(certificate.getPrivateKey());
    this.setCaName(certificate.getCaName());
    this.setCertificate(certificate.getCertificate());
  }

  public CertificateReader getParsedCertificate() {
    return this.parsedCertificate;
  }

  public String getCa() {
    return delegate.getCa();
  }

  public CertificateCredentialVersion setCa(String ca) {
    delegate.setCa(ca);
    return this;
  }

  public String getCertificate() {
    return delegate.getCertificate();
  }

  public CertificateCredentialVersion setCertificate(String certificate) {
    delegate.setCertificate(certificate);
    if (StringUtils.isNotEmpty(delegate.getCertificate())) {
      parsedCertificate = new CertificateReader(certificate);
    }
    return this;
  }

  public String getPrivateKey() {
    return (String) super.getValue();
  }

  public CertificateCredentialVersion setPrivateKey(String privateKey) {
    if (privateKey != null) {
      super.setValue(privateKey);
    }
    return this;
  }

  public String getCaName() {
    return delegate.getCaName();
  }

  public CertificateCredentialVersion setCaName(String caName) {
    delegate.setCaName(caName);
    return this;
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }

  public void rotate() {
    String decryptedPrivateKey = this.getPrivateKey();
    this.setPrivateKey(decryptedPrivateKey);
  }

  public boolean matchesGenerationParameters(GenerationParameters generationParameters) {
    final CertificateGenerationParameters parameters = (CertificateGenerationParameters) generationParameters;
    final CertificateGenerationParameters existingGenerationParameters = new CertificateGenerationParameters(getParsedCertificate(), getCaName());
    return existingGenerationParameters.equals(parameters);
  }
}
