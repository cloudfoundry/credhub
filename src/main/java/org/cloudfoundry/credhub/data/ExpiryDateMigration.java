package org.cloudfoundry.credhub.data;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.repository.CredentialVersionRepository;
import org.cloudfoundry.credhub.util.CertificateReader;

@Component
public class ExpiryDateMigration {
  private final CredentialVersionRepository credentialVersionRepository;

  @Autowired
  public ExpiryDateMigration(final CredentialVersionRepository credentialVersionRepository) {
    super();
    this.credentialVersionRepository = credentialVersionRepository;
  }

  public void migrate() {
    final List<CredentialVersionData> data = credentialVersionRepository.findAllVersionsWithNullExpirationDate();

    for (final CredentialVersionData version : data) {
      if (version instanceof CertificateCredentialVersionData) {
        final String certificate = ((CertificateCredentialVersionData) version).getCertificate();
        final CertificateReader reader = new CertificateReader(certificate);
        ((CertificateCredentialVersionData) version).setExpiryDate(reader.getNotAfter());
      }
    }
    credentialVersionRepository.saveAll(data);
  }
}
