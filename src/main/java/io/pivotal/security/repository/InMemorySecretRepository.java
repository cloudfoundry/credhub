package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedSecret;
import org.springframework.data.repository.CrudRepository;

interface InMemorySecretRepository extends CrudRepository<NamedSecret, Long> {
  NamedSecret findOneByName(String name);
}
