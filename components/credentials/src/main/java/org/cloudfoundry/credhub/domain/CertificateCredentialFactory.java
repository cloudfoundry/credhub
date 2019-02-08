package org.cloudfoundry.credhub.domain;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.entity.Credential;

@Component
public class CertificateCredentialFactory {

  private final Encryptor encryptor;

  @Autowired
  CertificateCredentialFactory(final Encryptor encryptor) {
    super();
    this.encryptor = encryptor;
  }

  public CertificateCredentialVersion makeNewCredentialVersion(
    final Credential certificateCredential,
    final CertificateCredentialValue credentialValue
  ) {
    final CertificateCredentialVersion version = new CertificateCredentialVersion(credentialValue, encryptor);
    version.setCredential(certificateCredential);

    return version;
  }
}
