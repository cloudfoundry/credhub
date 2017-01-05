package io.pivotal.security.data;

import io.pivotal.security.entity.EncryptionKeyCanary;
import io.pivotal.security.repository.EncryptionKeyCanaryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class EncryptionKeyCanaryDataService {
  @Autowired
  EncryptionKeyCanaryRepository encryptionKeyCanaryRepository;

  @Autowired
  JdbcTemplate jdbcTemplate;

  public EncryptionKeyCanary save(EncryptionKeyCanary canary) {
    return encryptionKeyCanaryRepository.save(canary);
  }

  public List<EncryptionKeyCanary> findAll() {
    return encryptionKeyCanaryRepository.findAll();
  }
}
