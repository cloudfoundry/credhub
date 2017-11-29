package io.pivotal.security.data;

import io.pivotal.security.entity.Credential;
import io.pivotal.security.repository.CertificateRepository;
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
}
