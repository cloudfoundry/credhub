package io.pivotal.security.fake;

import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.repository.OperationAuditRecordRepository;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.util.ArrayList;
import java.util.List;

public class FakeOperationAuditRecordRepository implements OperationAuditRecordRepository {
  private final FakeTransactionManager transactionManager;
  private List<OperationAuditRecord> auditRecords;

  private boolean shouldThrow = false;

  public FakeOperationAuditRecordRepository(FakeTransactionManager transactionManager) {
    this.transactionManager = transactionManager;
    this.auditRecords = new ArrayList<>();
  }

  @Override
  public <S extends OperationAuditRecord> S save(S entity) {
    transactionManager.currentTransaction.enqueue(() -> {
      OperationAuditRecord copy = new OperationAuditRecord(
          entity.getNow(),
          entity.getOperation(),
          entity.getUserId(),
          entity.getUserName(),
          entity.getUaaUrl(),
          entity.getTokenIssued(),
          entity.getTokenExpires(),
          entity.getHostName(),
          entity.getMethod(),
          entity.getPath(),
          entity.getQueryParameters(),
          entity.getStatusCode(),
          entity.getRequesterIp(),
          entity.getXForwardedFor(),
          entity.getClientId(),
          entity.getScope(),
          entity.getGrantType(),
          entity.isSuccess()
      );
      auditRecords.add(copy);
    });
    if (shouldThrow) throw new RuntimeException(getClass().getSimpleName());
    return entity;
  }

  @Override
  public OperationAuditRecord findOne(Long aLong) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean exists(Long aLong) {
    throw new UnsupportedOperationException();
  }

  @Override
  public List<OperationAuditRecord> findAll() {
    return auditRecords;
  }

  @Override
  public List<OperationAuditRecord> findAll(Sort sort) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Page<OperationAuditRecord> findAll(Pageable pageable) {
    throw new UnsupportedOperationException();
  }

  @Override
  public List<OperationAuditRecord> findAll(Iterable<Long> longs) {
    throw new UnsupportedOperationException();
  }

  @Override
  public long count() {
    return auditRecords.size();
  }

  @Override
  public void delete(Long aLong) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void delete(OperationAuditRecord entity) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void delete(Iterable<? extends OperationAuditRecord> entities) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void deleteAll() {
    auditRecords.clear();
  }

  @Override
  public void flush() {
    throw new UnsupportedOperationException();
  }

  @Override
  public void deleteInBatch(Iterable<OperationAuditRecord> entities) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void deleteAllInBatch() {
    throw new UnsupportedOperationException();
  }

  @Override
  public OperationAuditRecord getOne(Long aLong) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends OperationAuditRecord> S saveAndFlush(S entity) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends OperationAuditRecord> List<S> save(Iterable<S> entities) {
    throw new UnsupportedOperationException();
  }

  public void failOnSave() {
    shouldThrow = true;
  }

  @Override
  public <S extends OperationAuditRecord> List<S> findAll(Example<S> example) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends OperationAuditRecord> List<S> findAll(Example<S> example, Sort sort) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends OperationAuditRecord> S findOne(Example<S> example) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends OperationAuditRecord> Page<S> findAll(Example<S> example, Pageable pageable) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends OperationAuditRecord> long count(Example<S> example) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends OperationAuditRecord> boolean exists(Example<S> example) {
    throw new UnsupportedOperationException();
  }
}
