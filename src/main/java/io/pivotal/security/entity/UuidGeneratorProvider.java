package io.pivotal.security.entity;

import io.pivotal.security.util.UuidGenerator;

class UuidGeneratorProvider {
  public static UuidGenerator getInstance() {
    return BeanStaticProvider.getInstance(UuidGenerator.class);
  }
}
