package io.pivotal.security;

import org.junit.After;
import org.junit.Before;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;

public class MockitoSpringTest {
  @Autowired
  private AutowireCapableBeanFactory beanFactory;

  @Before
  public void setUpMockito() {
    MockitoAnnotations.initMocks(this);
  }

  @After
  public void cleanContext() throws IllegalAccessException {
    cleanClass(getClass());
  }

  private void cleanClass(Class klazz) throws IllegalAccessException {
    if (klazz != MockitoSpringTest.class) {
      cleanClass(klazz.getSuperclass());
    }
    for (Field field : klazz.getDeclaredFields()) {
      for (Annotation annotation : field.getAnnotations()) {
        if (annotation.annotationType().getSimpleName().equals(InjectMocks.class.getSimpleName())) {
          field.setAccessible(true);
          beanFactory.autowireBean(field.get(this));
        }
      }
    }
  }

}
