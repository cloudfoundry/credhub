package io.pivotal.security.fake;

import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.TransactionStatus;

import java.util.ArrayList;
import java.util.List;

public class FakeTransactionManager implements PlatformTransactionManager {

  Tx currentTransaction;

  @Override
  public TransactionStatus getTransaction(TransactionDefinition definition) throws TransactionException {
    if (currentTransaction != null) {
      throw new RuntimeException();
    }
    currentTransaction = new Tx();
    return null;
  }

  @Override
  public void commit(TransactionStatus status) throws TransactionException {
    currentTransaction.commit();
  }

  @Override
  public void rollback(TransactionStatus status) throws TransactionException {
    currentTransaction.rollback();
    currentTransaction = null;
  }

  static class Tx {
    final List<Operation> operations = new ArrayList<>();
    private boolean completed = false;

    void enqueue(Operation o) {
      operations.add(o);
    }

    void commit() {
      if (completed) throw new RuntimeException("can't commit completed transaction");
      completed = true;
      operations.forEach(Operation::perform);
    }

    void rollback() {
      if (completed) throw new RuntimeException("can't rollback completed transaction");
    }

    interface Operation {
      void perform();
    }
  }
}
