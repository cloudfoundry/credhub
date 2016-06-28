package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedAuthority;
import org.springframework.data.jpa.repository.JpaRepository;

public interface InMemoryAuthorityRepository extends JpaRepository<NamedAuthority, Long> {
  NamedAuthority findOneByName(String name);
}
