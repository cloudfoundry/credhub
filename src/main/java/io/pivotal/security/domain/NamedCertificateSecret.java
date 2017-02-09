package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedCertificateSecretData;
import io.pivotal.security.view.SecretKind;

public class NamedCertificateSecret extends NamedSecret<NamedCertificateSecret> {
  private NamedCertificateSecretData delegate;

  public NamedCertificateSecret(NamedCertificateSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public NamedCertificateSecret(String name) {
    this(new NamedCertificateSecretData(name));
  }

  public NamedCertificateSecret() {
    this(new NamedCertificateSecretData());
  }

  public String getCa() {
    return delegate.getCa();
  }

  public NamedCertificateSecret setCa(String ca) {
    delegate.setCa(ca);
    return this;
  }

  public String getCertificate() {
    return delegate.getCertificate();
  }

  public NamedCertificateSecret setCertificate(String certificate) {
    delegate.setCertificate(certificate);
    return this;
  }

  public String getPrivateKey() {
    return delegate.getPrivateKey();
  }

  public NamedCertificateSecret setPrivateKey(String privateKey) {
    delegate.setPrivateKey(privateKey);
    return this;
  }

  public NamedCertificateSecret setCaName(String caName) {
    delegate.setCaName(caName);
    return this;
  }

  public String getCaName() {
    return delegate.getCaName();
  }

  @Override
  public SecretKind getKind() {
    return delegate.getKind();
  }

  @Override
  public String getSecretType() {
    return delegate.getSecretType();
  }

  @Override
  void copyIntoImpl(NamedCertificateSecret copy) {
    delegate.copyInto(copy.delegate);
  }
}
