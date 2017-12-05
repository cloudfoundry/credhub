package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.repository.CertificateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CertificateDataService {
  private final CertificateRepository certificateRepository;

  @Autowired
  public CertificateDataService(CertificateRepository certificateRepository) {
    this.certificateRepository = certificateRepository;
  }

  public List<Credential> findAll() {
    return certificateRepository.findAllCertificates();
  }

  public Credential findByName(String name) {
    return certificateRepository.findCertificateByName(name);
  }
}
