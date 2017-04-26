package io.pivotal.security.repository;

import io.pivotal.security.entity.CredentialName;
import java.util.UUID;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface CredentialNameRepository extends JpaRepository<CredentialName, UUID> {

  @Transactional
  long deleteByNameIgnoreCase(String name);

  default CredentialName findCredentialName(String name){
    return findOneByNameIgnoreCase(StringUtils.prependIfMissing(name, "/"));
  }

  CredentialName findOneByNameIgnoreCase(String name);
}
