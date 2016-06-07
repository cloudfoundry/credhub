package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedSecret;
import org.springframework.data.jpa.repository.JpaRepository;

interface InMemorySecretRepository extends JpaRepository<NamedSecret, Long> {
  NamedSecret findOneByName(String name);
}
