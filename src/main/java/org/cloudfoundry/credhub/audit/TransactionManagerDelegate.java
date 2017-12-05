package org.cloudfoundry.credhub.audit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.TransactionStatus;

@Component
class TransactionManagerDelegate {
  @Autowired
  private PlatformTransactionManager delegate;

  TransactionStatus getTransaction(TransactionDefinition definition) throws TransactionException {
    return delegate.getTransaction(definition);
  }

  void commit(TransactionStatus status) throws TransactionException {
    delegate.commit(status);
  }

  void rollback(TransactionStatus status) throws TransactionException {
    delegate.rollback(status);
  }
}
