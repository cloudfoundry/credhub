package org.cloudfoundry.credhub.data;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;
import org.cloudfoundry.credhub.repositories.EncryptionKeyCanaryRepository;

@Service
public class EncryptionKeyCanaryDataService {
  private final EncryptionKeyCanaryRepository encryptionKeyCanaryRepository;

  @Autowired
  EncryptionKeyCanaryDataService(final EncryptionKeyCanaryRepository encryptionKeyCanaryRepository) {
    super();
    this.encryptionKeyCanaryRepository = encryptionKeyCanaryRepository;
  }

  public EncryptionKeyCanary save(final EncryptionKeyCanary canary) {
    return encryptionKeyCanaryRepository.save(canary);
  }

  public List<EncryptionKeyCanary> findAll() {
    return encryptionKeyCanaryRepository.findAll();
  }

  public void delete(final List<UUID> uuids) {
    encryptionKeyCanaryRepository.deleteByUuidIn(uuids);
  }
}
