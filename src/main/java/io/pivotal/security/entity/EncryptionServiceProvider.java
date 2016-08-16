package io.pivotal.security.entity;

import io.pivotal.security.service.EncryptionService;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

@Component
public class EncryptionServiceProvider implements ApplicationContextAware {

  private static ApplicationContext applicationContext;

  @Override
  public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
    EncryptionServiceProvider.applicationContext = applicationContext;
  }

  public static EncryptionService getInstance() {
    return applicationContext.getBean(EncryptionService.class);
  }
}
