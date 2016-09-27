package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedCanary;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CanaryRepository extends JpaRepository<NamedCanary, Long> {
  NamedCanary findOneByName(String name);
}
