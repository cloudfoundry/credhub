package io.pivotal.security.data;

import io.pivotal.security.entity.EncryptionKeyCanary;
import io.pivotal.security.repository.EncryptionKeyCanaryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class EncryptionKeyCanaryDataService {
  @Autowired
  EncryptionKeyCanaryRepository encryptionKeyCanaryRepository;

  public EncryptionKeyCanary save(EncryptionKeyCanary canary) {
    return encryptionKeyCanaryRepository.save(canary);
  }

  public EncryptionKeyCanary find(String name) {
    return encryptionKeyCanaryRepository.findOneByName(name);
  }
}
