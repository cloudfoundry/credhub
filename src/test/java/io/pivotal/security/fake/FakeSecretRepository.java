package io.pivotal.security.fake;

import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.repository.SecretRepository;
import org.springframework.data.domain.*;

import java.util.List;
import java.util.UUID;

public class FakeSecretRepository implements SecretRepository {
  public int count = 0;

  private final FakeTransactionManager transactionManager;

  public FakeSecretRepository() {
    this.transactionManager = new FakeTransactionManager();
  }

  public FakeSecretRepository(FakeTransactionManager transactionManager) {
    this.transactionManager = transactionManager;
  }

  @Override
  public NamedSecret findFirstByNameIgnoreCaseOrderByVersionCreatedAtDesc(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public NamedSecret findOneByUuid(UUID uuid) {
    throw new UnsupportedOperationException();
  }

  @Override
  public List<NamedSecret> deleteByNameIgnoreCase(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecret> S save(S entity) {
    transactionManager.currentTransaction.enqueue(() -> {
      count++;
    });
    return entity;
  }

  @Override
  public NamedSecret findOne(UUID aLong) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean exists(UUID aLong) {
    throw new UnsupportedOperationException();
  }

  @Override
  public List<NamedSecret> findAll() {
    throw new UnsupportedOperationException();
  }

  @Override
  public List<NamedSecret> findAll(Sort sort) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Page<NamedSecret> findAll(Pageable pageable) {
    throw new UnsupportedOperationException();
  }

  @Override
  public List<NamedSecret> findAll(Iterable<UUID> longs) {
    throw new UnsupportedOperationException();
  }

  @Override
  public List<NamedSecret> findAllByNameIgnoreCase(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Long countByEncryptionKeyUuidNot(UUID encryptionKeyUuid) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Long countByEncryptionKeyUuidIn(List<UUID> uuids) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Slice<NamedSecret> findByEncryptionKeyUuidIn(List<UUID> encryptionKeyUuids, Pageable page) {
    throw new UnsupportedOperationException();
  }

  @Override
  public long count() {
    return count;
  }

  @Override
  public void delete(UUID aLong) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void delete(NamedSecret entity) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void delete(Iterable<? extends NamedSecret> entities) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void deleteAll() {
    throw new UnsupportedOperationException();
  }

  @Override
  public void flush() {
    throw new UnsupportedOperationException();
  }

  @Override
  public void deleteInBatch(Iterable<NamedSecret> entities) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void deleteAllInBatch() {
    throw new UnsupportedOperationException();
  }

  @Override
  public NamedSecret getOne(UUID aLong) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecret> S saveAndFlush(S entity) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecret> List<S> save(Iterable<S> entities) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecret> List<S> findAll(Example<S> example) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecret> List<S> findAll(Example<S> example, Sort sort) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecret> S findOne(Example<S> example) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecret> Page<S> findAll(Example<S> example, Pageable pageable) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecret> long count(Example<S> example) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecret> boolean exists(Example<S> example) {
    throw new UnsupportedOperationException();
  }
}
