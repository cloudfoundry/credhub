package io.pivotal.security.util;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class InstantFactoryBean implements FactoryBean<Instant> {

  @Override
  public Instant getObject() {
    try {
      return Instant.now();
    } catch (Exception e){
      throw new RuntimeException(e);
    }
  }

  @Override
  public Class<?> getObjectType() {
    return Instant.class;
  }

  @Override
  public boolean isSingleton() {
    return false;
  }
}
