package io.pivotal.security.entity;

import io.pivotal.security.service.EncryptionService;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

class EncryptionServiceProvider {
  public static EncryptionService getInstance() {
    return BeanStaticProvider.getInstance(EncryptionService.class);
  }
}
