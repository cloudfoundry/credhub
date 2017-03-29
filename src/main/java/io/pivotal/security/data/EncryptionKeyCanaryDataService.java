package io.pivotal.security.data;

import io.pivotal.security.entity.EncryptionKeyCanary;
import io.pivotal.security.repository.EncryptionKeyCanaryRepository;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

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

  public void delete(EncryptionKeyCanary canary) {
    encryptionKeyCanaryRepository.delete(canary);
  }
}
