package io.pivotal.security.fake;

import io.pivotal.security.entity.NamedSecretData;
import io.pivotal.security.repository.SecretRepository;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.Sort;

public class FakeSecretRepository implements SecretRepository {

  private final FakeTransactionManager transactionManager;
  public int count = 0;

  public FakeSecretRepository() {
    this.transactionManager = new FakeTransactionManager();
  }

  public FakeSecretRepository(FakeTransactionManager transactionManager) {
    this.transactionManager = transactionManager;
  }

  @Override
  public NamedSecretData findOneByUuid(UUID uuid) {
    throw new UnsupportedOperationException();
  }

  @Override
  public long deleteBySecretNameUuid(UUID secretNameUuid) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecretData> S save(S entity) {
    transactionManager.currentTransaction.enqueue(() -> {
      count++;
    });
    return entity;
  }

  @Override
  public <S extends NamedSecretData> List<S> save(Iterable<S> entities) {
    throw new UnsupportedOperationException();
  }

  @Override
  public NamedSecretData findOne(UUID along) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecretData> S findOne(Example<S> example) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean exists(UUID along) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecretData> boolean exists(Example<S> example) {
    throw new UnsupportedOperationException();
  }

  @Override
  public List<NamedSecretData> findAll() {
    throw new UnsupportedOperationException();
  }

  @Override
  public List<NamedSecretData> findAll(Sort sort) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Page<NamedSecretData> findAll(Pageable pageable) {
    throw new UnsupportedOperationException();
  }

  @Override
  public List<NamedSecretData> findAll(Iterable<UUID> longs) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecretData> List<S> findAll(Example<S> example) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecretData> Page<S> findAll(Example<S> example, Pageable pageable) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecretData> List<S> findAll(Example<S> example, Sort sort) {
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
  public Slice<NamedSecretData> findByEncryptionKeyUuidIn(List<UUID> encryptionKeyUuids,
      Pageable page) {
    throw new UnsupportedOperationException();
  }

  @Override
  public List<NamedSecretData> findAllBySecretNameUuid(UUID uuid) {
    throw new UnsupportedOperationException();
  }

  @Override
  public NamedSecretData findFirstBySecretNameUuidOrderByVersionCreatedAtDesc(UUID uuid) {
    throw new UnsupportedOperationException();
  }

  @Override
  public long count() {
    return count;
  }

  @Override
  public <S extends NamedSecretData> long count(Example<S> example) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void delete(UUID along) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void delete(NamedSecretData entity) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void delete(Iterable<? extends NamedSecretData> entities) {
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
  public void deleteInBatch(Iterable<NamedSecretData> entities) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void deleteAllInBatch() {
    throw new UnsupportedOperationException();
  }

  @Override
  public NamedSecretData getOne(UUID along) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends NamedSecretData> S saveAndFlush(S entity) {
    throw new UnsupportedOperationException();
  }
}
