package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedSecret;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SecretRepository extends JpaRepository<NamedSecret, Long> {
  NamedSecret findOneByName(String name);
  NamedSecret findOneByUuid(String uuid);
  List<NamedSecret> findByNameContainingOrderByUpdatedAtDesc(String nameSubstring);
}
