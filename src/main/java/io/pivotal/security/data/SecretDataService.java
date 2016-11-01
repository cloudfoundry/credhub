package io.pivotal.security.data;

import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.repository.SecretRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SecretDataService {

  @Autowired
  public SecretRepository secretRepository;

  public NamedSecret save(NamedSecret namedSecret) {
    return secretRepository.saveAndFlush(namedSecret);
  }

  public List<String> findAllPaths(Boolean findPaths) {
    return secretRepository.findAllPaths(findPaths);
  }

  public NamedSecret findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(String name) {
    return secretRepository.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(name);
  }

  public NamedSecret findOneByUuid(String uuid) {
    return secretRepository.findOneByUuid(uuid);
  }

  public List<NamedSecret> findByNameIgnoreCaseContainingOrderByUpdatedAtDesc(String name) {
    return secretRepository.findByNameIgnoreCaseContainingOrderByUpdatedAtDesc(name);
  }

  public List<NamedSecret> findByNameIgnoreCaseStartingWithOrderByUpdatedAtDesc(String name) {
    return secretRepository.findByNameIgnoreCaseStartingWithOrderByUpdatedAtDesc(name);
  }

  public void delete(NamedSecret secret) {
    secretRepository.delete(secret);
  }
}
