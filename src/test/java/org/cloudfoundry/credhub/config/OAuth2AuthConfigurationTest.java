package org.cloudfoundry.credhub.config;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.lang.reflect.Field;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = {"unit-test", "OAuth2ConfigurationTest"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest
@Transactional
public class OAuth2AuthConfigurationTest {

  @Autowired
  SecurityAutoConfiguration securityAutoConfiguration;

  @Autowired
  JwtAccessTokenConverter accessTokenConverter;

  @Test
  public void shouldDisableBasicAuth() {
    assertThat(securityAutoConfiguration.securityProperties().getBasic().isEnabled(),
        equalTo(false));
  }

  @Test
  public void shouldIncludeGrantTypeInItsTokenConverter() throws NoSuchFieldException, IllegalAccessException {
    DefaultAccessTokenConverter converter = (DefaultAccessTokenConverter) accessTokenConverter
        .getAccessTokenConverter();
    Field includeGrantType = converter.getClass().getDeclaredField("includeGrantType");
    includeGrantType.setAccessible(true);
    assertThat(includeGrantType.get(converter), equalTo(true));
  }

  @Configuration
  @Import(CredentialManagerApp.class)
  public static class TestConfiguration {
    // this class is only to trigger Configuration loading for test purposes

    @Bean
    @Primary
    @Profile("OAuth2ConfigurationTest")
    public JwtAccessTokenConverter symmetricTokenConverter(
        DefaultAccessTokenConverter defaultAccessTokenConverter) throws Exception {
      JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
      jwtAccessTokenConverter.setAccessTokenConverter(defaultAccessTokenConverter);
      jwtAccessTokenConverter.afterPropertiesSet();
      return jwtAccessTokenConverter;
    }
  }
}
