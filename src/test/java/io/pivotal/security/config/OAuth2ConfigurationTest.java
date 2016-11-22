package io.pivotal.security.config;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.util.DatabaseProfileResolver;
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
import org.springframework.web.context.WebApplicationContext;

import java.lang.reflect.Field;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test", "OAuth2ConfigurationTest"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest
public class OAuth2ConfigurationTest {

  @Autowired
  WebApplicationContext applicationContext;

  @Autowired
  SecurityAutoConfiguration securityAutoConfiguration;

  @Autowired
  OAuth2Configuration oAuth2Configuration;

  @Autowired
  JwtAccessTokenConverter accessTokenConverter;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      oAuth2Configuration.init();
    });

    it("should have obscure user populated", () -> {
      oAuth2Configuration.init();
      assertThat(oAuth2Configuration.securityProperties.getUser().getName().length(), equalTo(12));
      assertThat(oAuth2Configuration.securityProperties.getUser().getName(), not(equalTo("user")));
      assertThat(oAuth2Configuration.securityProperties.getUser().getRole().size(), equalTo(0));
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
