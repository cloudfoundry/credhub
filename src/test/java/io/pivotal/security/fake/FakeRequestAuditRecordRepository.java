package io.pivotal.security.fake;

import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.util.ArrayList;
import java.util.List;

public class FakeRequestAuditRecordRepository implements RequestAuditRecordRepository {

  private final FakeTransactionManager transactionManager;
  private List<RequestAuditRecord> auditRecords;

  private boolean shouldThrow = false;

  public FakeRequestAuditRecordRepository(FakeTransactionManager transactionManager) {
    this.transactionManager = transactionManager;
    this.auditRecords = new ArrayList<>();
  }

  @Override
  public <S extends RequestAuditRecord> S save(S entity) {
    transactionManager.currentTransaction.enqueue(() -> {
      RequestAuditRecord copy = new RequestAuditRecord(
          entity.getAuthMethod(),
          entity.getNow(),
          entity.getCredentialName(),
          entity.getOperation(),
          entity.getUserId(),
          entity.getUserName(),
          entity.getUaaUrl(),
          entity.getAuthValidFrom(),
          entity.getAuthValidUntil(),
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
    if (shouldThrow) {
      throw new TestTransactionException(getClass().getSimpleName());
    }
    return entity;
  }

  @Override
  public <S extends RequestAuditRecord> List<S> save(Iterable<S> entities) {
    throw new UnsupportedOperationException();
  }

  @Override
  public RequestAuditRecord findOne(Long along) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends RequestAuditRecord> S findOne(Example<S> example) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean exists(Long along) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends RequestAuditRecord> boolean exists(Example<S> example) {
    throw new UnsupportedOperationException();
  }

  @Override
  public List<RequestAuditRecord> findAll() {
    return auditRecords;
  }

  @Override
  public List<RequestAuditRecord> findAll(Sort sort) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Page<RequestAuditRecord> findAll(Pageable pageable) {
    throw new UnsupportedOperationException();
  }

  @Override
  public List<RequestAuditRecord> findAll(Iterable<Long> longs) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends RequestAuditRecord> List<S> findAll(Example<S> example, Sort sort) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends RequestAuditRecord> List<S> findAll(Example<S> example) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends RequestAuditRecord> Page<S> findAll(Example<S> example, Pageable pageable) {
    throw new UnsupportedOperationException();
  }

  @Override
  public long count() {
    return auditRecords.size();
  }

  @Override
  public <S extends RequestAuditRecord> long count(Example<S> example) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void delete(Long along) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void delete(RequestAuditRecord entity) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void delete(Iterable<? extends RequestAuditRecord> entities) {
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
  public void deleteInBatch(Iterable<RequestAuditRecord> entities) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void deleteAllInBatch() {
    throw new UnsupportedOperationException();
  }

  @Override
  public RequestAuditRecord getOne(Long along) {
    throw new UnsupportedOperationException();
  }

  @Override
  public <S extends RequestAuditRecord> S saveAndFlush(S entity) {
    throw new UnsupportedOperationException();
  }

  public void failOnSave() {
    shouldThrow = true;
  }
}
