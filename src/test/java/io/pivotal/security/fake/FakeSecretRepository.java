package io.pivotal.security.fake;

import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.repository.SecretRepository;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.util.List;

public class FakeSecretRepository implements SecretRepository {
  public int count = 0;

  private final FakeTransactionManager transactionManager;

  public FakeSecretRepository(FakeTransactionManager transactionManager) {
    this.transactionManager = transactionManager;
  }

  @Override
  public NamedSecret findOneByNameIgnoreCase(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public NamedSecret findOneByUuid(String uuid) {
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
  public NamedSecret findOne(Long aLong) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean exists(Long aLong) {
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
  public List<NamedSecret> findAll(Iterable<Long> longs) {
    throw new UnsupportedOperationException();
  }

  @Override
  public List<NamedSecret> findByNameIgnoreCaseContainingOrderByUpdatedAtDesc(String nameSubstring) {
    throw new UnsupportedOperationException();
  }

  @Override
  public List<NamedSecret> findByNameIgnoreCaseStartingWithOrderByUpdatedAtDesc(String nameSubstring) {
    throw new UnsupportedOperationException();
  }

  @Override
  public long count() {
    return count;
  }

  @Override
  public void delete(Long aLong) {
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
  public NamedSecret getOne(Long aLong) {
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
