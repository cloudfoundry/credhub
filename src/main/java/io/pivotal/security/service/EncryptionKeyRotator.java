package io.pivotal.security.service;

import io.pivotal.security.data.CertificateAuthorityDataService;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.SecretEncryptionHelper;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class EncryptionKeyRotator {
  private final SecretEncryptionHelper secretEncryptionHelper;
  private final SecretDataService secretDataService;
  private final CertificateAuthorityDataService certificateAuthorityDataService;

  EncryptionKeyRotator(
      SecretEncryptionHelper secretEncryptionHelper,
      SecretDataService secretDataService,
      CertificateAuthorityDataService certificateAuthorityDataService
  ) {
    this.secretEncryptionHelper = secretEncryptionHelper;
    this.secretDataService = secretDataService;
    this.certificateAuthorityDataService = certificateAuthorityDataService;

    rotate();
  }

  // Synchronized to ensure that nothing happens until everything has been rotated.
  // This is the naive version!!!
  // Future stories should improve this (performance, error handling, etc.).
  private synchronized void rotate() {
    List<NamedSecret> secrets = secretDataService.findAll();
    List<NamedCertificateAuthority> certificateAuthorities = certificateAuthorityDataService.findAll();

    for (NamedSecret secret : secrets) {
      secretEncryptionHelper.rotate(secret);
      secretDataService.save(secret);
    }

    for (NamedCertificateAuthority certificateAuthority : certificateAuthorities) {
      secretEncryptionHelper.rotate(certificateAuthority);
      certificateAuthorityDataService.save(certificateAuthority);
    }
  }
}
