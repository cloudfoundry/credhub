package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;
import org.cloudfoundry.credhub.repository.EncryptionKeyCanaryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class EncryptionKeyCanaryDataService {
  private final EncryptionKeyCanaryRepository encryptionKeyCanaryRepository;

  @Autowired
  EncryptionKeyCanaryDataService(EncryptionKeyCanaryRepository encryptionKeyCanaryRepository) {
    this.encryptionKeyCanaryRepository = encryptionKeyCanaryRepository;
  }

  public EncryptionKeyCanary save(EncryptionKeyCanary canary) {
    return encryptionKeyCanaryRepository.save(canary);
  }

  public List<EncryptionKeyCanary> findAll() {
    return encryptionKeyCanaryRepository.findAll();
  }

  public void delete(List<UUID> uuids) {
    encryptionKeyCanaryRepository.deleteByUuidIn(uuids);
  }
}
