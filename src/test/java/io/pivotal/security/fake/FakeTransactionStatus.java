package io.pivotal.security.fake;

import org.springframework.transaction.TransactionException;
import org.springframework.transaction.TransactionStatus;

import java.util.ArrayList;
import java.util.List;

public class FakeTransactionStatus implements TransactionStatus {
  private final List<Operation> operations = new ArrayList<>();
  private boolean completed = false;

  void enqueue(Operation o) {
    operations.add(o);
  }

  void complete() {
    completed = true;
  }

  void commit() {
    if (completed) {
      throw new TestTransactionException("can't commit completed transaction");
    }
    completed = true;
    operations.forEach(Operation::perform);
  }

  void rollback() {
    if (completed) {
      throw new TestTransactionException("can't rollback completed transaction");
    }
    completed = true;
    operations.clear();
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
