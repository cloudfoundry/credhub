package io.pivotal.security.fake;

import io.pivotal.security.entity.NamedSecretData;

public class FakeRepository {
  private final FakeTransactionManager transactionManager;
  private int count = 0;

  public FakeRepository(FakeTransactionManager transactionManager) {
    this.transactionManager = transactionManager;
  }

  public <S extends NamedSecretData> S save(S entity) {
    transactionManager.currentTransaction.enqueue(() -> {
      count++;
    });
    return entity;
  }

  public long count() {
    return count;
  }
}
