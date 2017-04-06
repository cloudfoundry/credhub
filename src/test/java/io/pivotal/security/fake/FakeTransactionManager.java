package io.pivotal.security.fake;

import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.TransactionStatus;

public class FakeTransactionManager implements PlatformTransactionManager {

  FakeTransactionStatus currentTransaction;
  private boolean shouldThrow;

  @Override
  public TransactionStatus getTransaction(TransactionDefinition definition) throws TransactionException {
    if (currentTransaction == null || currentTransaction.isCompleted()) {
      currentTransaction = new FakeTransactionStatus();
    }

    return currentTransaction;
  }

  @Override
  public void commit(TransactionStatus status) throws TransactionException {
    if (shouldThrow) {
      currentTransaction.complete();
      throw new TestTransactionException("can't commit transaction");
    }
    currentTransaction.commit();
  }

  @Override
  public void rollback(TransactionStatus status) throws TransactionException {
    currentTransaction.rollback();
  }

  public void failOnCommit() {
    shouldThrow = true;
  }

  public boolean hasOpenTransaction() {
    return currentTransaction != null && !currentTransaction.isCompleted();
  }
}
