package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.entity.Credential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CertificateCredentialFactory {

  private final Encryptor encryptor;

  @Autowired
  CertificateCredentialFactory(Encryptor encryptor) {
    this.encryptor = encryptor;
  }

  public CertificateCredentialVersion makeNewCredentialVersion(
      Credential certificateCredential,
      CertificateCredentialValue credentialValue
  ) {
    CertificateCredentialVersion version = new CertificateCredentialVersion(credentialValue, encryptor);
    version.setCredential(certificateCredential);

    return version;
  }
}
