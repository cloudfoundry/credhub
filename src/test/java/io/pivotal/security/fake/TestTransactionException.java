package io.pivotal.security.fake;

import org.springframework.transaction.TransactionException;

class TestTransactionException extends TransactionException {
  TestTransactionException(String message) {
    super(message);
  }

  TestTransactionException() {
    this("test exception");
  }
}
