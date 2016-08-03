package io.pivotal.security.fake;

import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.TransactionStatus;

import java.util.ArrayList;
import java.util.List;

public class FakeTransactionManager implements PlatformTransactionManager {

  Tx currentTransaction;
  private boolean shouldThrow;

  @Override
  public TransactionStatus getTransaction(TransactionDefinition definition) throws TransactionException {
    if (currentTransaction != null) {
      throw new RuntimeException();
    }
    currentTransaction = new Tx();
    return currentTransaction;
  }

  @Override
  public void commit(TransactionStatus status) throws TransactionException {
    if (shouldThrow) {
      currentTransaction.complete();
      throw new RuntimeException("can't commit transaction");
    }
    currentTransaction.commit();
  }

  @Override
  public void rollback(TransactionStatus status) throws TransactionException {
    currentTransaction.rollback();
    currentTransaction = null;
  }

  public void failOnCommit() {
    shouldThrow = true;
  }

  public boolean hasOpenTransaction() {
    return currentTransaction != null && !currentTransaction.isCompleted();
  }

  static class Tx implements TransactionStatus {
    final List<Operation> operations = new ArrayList<>();
    private boolean completed = false;

    void enqueue(Operation o) {
      operations.add(o);
    }

    void complete() {
      completed = true;
    }

    void commit() {
      if (completed) throw new RuntimeException("can't commit completed transaction");
      completed = true;
      operations.forEach(Operation::perform);
    }

    void rollback() {
      if (completed) throw new RuntimeException("can't rollback completed transaction");
    }

    @Override
    public boolean isNewTransaction() {
      return false;
    }

    @Override
    public boolean hasSavepoint() {
      return false;
    }

    @Override
    public void setRollbackOnly() {

    }

    @Override
    public boolean isRollbackOnly() {
      return false;
    }

    @Override
    public void flush() {

    }

    @Override
    public boolean isCompleted() {
      return completed;
    }

    @Override
    public Object createSavepoint() throws TransactionException {
      return null;
    }

    @Override
    public void rollbackToSavepoint(Object savepoint) throws TransactionException {

    }

    @Override
    public void releaseSavepoint(Object savepoint) throws TransactionException {

    }

    interface Operation {
      void perform();
    }
  }
}
