package org.cloudfoundry.credhub.services;

import org.cloudfoundry.credhub.credential.CertificateCredentialValue;

public interface CertificateAuthorityService {
  CertificateCredentialValue findActiveVersion(String caName);

  CertificateCredentialValue findTransitionalVersion(String caName);
}
