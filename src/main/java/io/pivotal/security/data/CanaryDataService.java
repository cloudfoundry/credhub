package io.pivotal.security.data;

import io.pivotal.security.entity.NamedCanary;
import io.pivotal.security.repository.CanaryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CanaryDataService {
  @Autowired
  CanaryRepository canaryRepository;

  public NamedCanary save(NamedCanary canary) {
    return canaryRepository.save(canary);
  }

  public NamedCanary findOneByName(String name) {
    return canaryRepository.findOneByName(name);
  }
}
