package io.pivotal.security.fake;

import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.repository.SecretRepository;
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
  public NamedSecret findOneByName(String name) {
    return null;
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
    return null;
  }

  @Override
  public boolean exists(Long aLong) {
    return false;
  }

  @Override
  public List<NamedSecret> findAll() {
    return null;
  }

  @Override
  public List<NamedSecret> findAll(Sort sort) {
    return null;
  }

  @Override
  public Page<NamedSecret> findAll(Pageable pageable) {
    return null;
  }

  @Override
  public List<NamedSecret> findAll(Iterable<Long> longs) {
    return null;
  }

  @Override
  public long count() {
    return count;
  }

  @Override
  public void delete(Long aLong) {

  }

  @Override
  public void delete(NamedSecret entity) {

  }

  @Override
  public void delete(Iterable<? extends NamedSecret> entities) {

  }

  @Override
  public void deleteAll() {

  }

  @Override
  public void flush() {

  }

  @Override
  public void deleteInBatch(Iterable<NamedSecret> entities) {

  }

  @Override
  public void deleteAllInBatch() {

  }

  @Override
  public NamedSecret getOne(Long aLong) {
    return null;
  }

  @Override
  public <S extends NamedSecret> S saveAndFlush(S entity) {
    return null;
  }

  @Override
  public <S extends NamedSecret> List<S> save(Iterable<S> entities) {
    return null;
  }
}
