package io.pivotal.security.config;


import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

import java.lang.reflect.Field;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test", "OAuth2ConfigurationTest"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest
public class AuthConfigurationTest {

  @Autowired
  WebApplicationContext applicationContext;

  @Autowired
  SecurityAutoConfiguration securityAutoConfiguration;

  @Autowired
  AuthConfiguration authConfiguration;

  @Autowired
  JwtAccessTokenConverter accessTokenConverter;

  @Autowired
  SecurityProperties securityProperties;

  @Autowired
  WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  {
    wireAndUnwire(this, false);
    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    });

    it("should be configured to have basic auth disabled", () -> {
      assertThat(securityAutoConfiguration.securityProperties().getBasic().isEnabled(), equalTo(false));
    });

    it("should include grant type in its token converter", () -> {
      DefaultAccessTokenConverter converter = (DefaultAccessTokenConverter) accessTokenConverter.getAccessTokenConverter();
      Field includeGrantType = converter.getClass().getDeclaredField("includeGrantType");
      includeGrantType.setAccessible(true);
      assertThat(includeGrantType.get(converter), equalTo(true));
    });
  }

  @Configuration
  @Import(CredentialManagerApp.class)
  public static class TestConfiguration {
    // this class is only to trigger Configuration loading for test purposes

    @Bean
    @Primary
    @Profile("OAuth2ConfigurationTest")
    public JwtAccessTokenConverter symmetricTokenConverter(DefaultAccessTokenConverter defaultAccessTokenConverter) throws Exception {
      JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
      jwtAccessTokenConverter.setAccessTokenConverter(defaultAccessTokenConverter);
      jwtAccessTokenConverter.afterPropertiesSet();
      return jwtAccessTokenConverter;
    }
  }
}
