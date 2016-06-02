package io.pivotal.security.repository

import io.pivotal.security.entity.NamedSecret
import org.springframework.data.repository.CrudRepository

interface InMemorySecretRepository : CrudRepository<NamedSecret, Long> {
  fun findOneByName(name: String): NamedSecret?
}
