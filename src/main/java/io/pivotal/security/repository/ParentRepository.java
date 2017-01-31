package io.pivotal.security.repository;

import io.pivotal.security.entity.Parent;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ParentRepository extends JpaRepository<Parent, Long> {
  public Parent findByName(String name);

}
