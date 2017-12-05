package org.cloudfoundry.credhub.util;

import org.apache.commons.lang3.ArrayUtils;
import org.springframework.test.context.support.DefaultActiveProfilesResolver;

public class DatabaseProfileResolver extends DefaultActiveProfilesResolver {

  @Override
  public String[] resolve(Class<?> testClass) {
    return (String[]) ArrayUtils.addAll(new String[]{System.getProperty("spring.profiles.active")},
        super.resolve(testClass));
  }
}
