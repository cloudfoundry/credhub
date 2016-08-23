package io.pivotal.security.helper;

import org.springframework.data.repository.CrudRepository;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

public class CountMemo {
  private long count;
  private CrudRepository repository;

  public CountMemo(CrudRepository repository) {
    this.repository = repository;
  }

  public CountMemo mark() {
    count = repository.count();
    return this;
  }

  public void expectIncreaseOf(long increase) {
    assertThat(repository.count() - count, equalTo(increase));
  }
}
