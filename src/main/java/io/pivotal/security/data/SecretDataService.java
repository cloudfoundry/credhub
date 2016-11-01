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

  public List<String> findAllPaths() {
    return secretRepository.findAllPaths(true);
  }

  public NamedSecret findMostRecent(String name) {
    return secretRepository.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(name);
  }

  public NamedSecret findByUuid(String uuid) {
    return secretRepository.findOneByUuid(uuid);
  }

  public List<NamedSecret> findContainingName(String name) {
    return secretRepository.findByNameIgnoreCaseContainingOrderByUpdatedAtDesc(name);
  }

  public List<NamedSecret> findStartingWithName(String name) {
    if (!name.endsWith("/")) {
      name += "/";
    }
    return secretRepository.findByNameIgnoreCaseStartingWithOrderByUpdatedAtDesc(name);
  }

  public List<NamedSecret> delete(String name) {
    return secretRepository.deleteByNameIgnoreCase(name);
  }
}
