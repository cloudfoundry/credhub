package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedStringSecret;
import org.springframework.data.repository.CrudRepository;

interface InMemorySecretRepository extends CrudRepository<NamedStringSecret, Long> {
  NamedStringSecret findOneByName(String name);
}
