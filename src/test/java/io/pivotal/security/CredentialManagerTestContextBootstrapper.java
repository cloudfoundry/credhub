package io.pivotal.security;

import org.springframework.test.context.MergedContextConfiguration;
import org.springframework.test.context.web.WebTestContextBootstrapper;
import org.springframework.util.StringUtils;

import java.util.stream.Stream;

import static org.springframework.core.env.AbstractEnvironment.ACTIVE_PROFILES_PROPERTY_NAME;

public class CredentialManagerTestContextBootstrapper extends WebTestContextBootstrapper {

  @Override
  protected MergedContextConfiguration processMergedContextConfiguration(MergedContextConfiguration mergedConfig) {
    String[] environmentProfiles = StringUtils.commaDelimitedListToStringArray(System.getProperty(ACTIVE_PROFILES_PROPERTY_NAME));
    String[] activeProfiles = mergedConfig.getActiveProfiles();
    String[] mergedProfiles = Stream.concat(Stream.of(environmentProfiles), Stream.of(activeProfiles)).toArray(String[]::new);

    return super.processMergedContextConfiguration(new MergedContextConfiguration(
        mergedConfig.getTestClass(),
        mergedConfig.getLocations(),
        mergedConfig.getClasses(),
        mergedProfiles,
        mergedConfig.getContextLoader()
    ));
  }
}
