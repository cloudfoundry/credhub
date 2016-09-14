package io.pivotal.security.config;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.context.WebApplicationContext;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration
@WebAppConfiguration
@ActiveProfiles({"unit-test", "OAuth2ConfigurationTest"})
public class OAuth2ConfigurationTest {

  @Autowired
  WebApplicationContext applicationContext;

  @Autowired
  SecurityAutoConfiguration securityAutoConfiguration;

  @Mock
  GuidProvider guidProvider;

  @Mock
  ResourceServerProperties resourceServerProperties;

  @Autowired
  OAuth2Configuration oAuth2Configuration;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      when(guidProvider.getUUID()).thenReturn("my guid");
      final ResourceServerProperties.Jwt jwt = mock(ResourceServerProperties.Jwt.class);
      when(resourceServerProperties.getJwt()).thenReturn(jwt);
      when(jwt.getKeyValue()).thenReturn("");

      oAuth2Configuration.guidProvider = guidProvider;
    });

    it("should have obscure user/pass populated", () -> {
      oAuth2Configuration.init();
      assertThat(oAuth2Configuration.securityProperties.getUser().getName(), equalTo("my guid"));
      assertThat(oAuth2Configuration.securityProperties.getUser().getPassword(), equalTo("my guid"));
      assertThat(oAuth2Configuration.securityProperties.getUser().getRole().size(), equalTo(0));
    });

    it("should be configured to have basic auth disabled", () -> {
      assertThat(securityAutoConfiguration.securityProperties().getBasic().isEnabled(), equalTo(false));
    });

  }

  @Configuration
  @Import(CredentialManagerApp.class)
  public static class TestConfiguration {
    // this class is only to trigger Configuration loading for test purposes

    @Bean
    @Primary
    @Profile("OAuth2ConfigurationTest")
    public JwtAccessTokenConverter symmetricTokenConverter() throws Exception {
      return new JwtAccessTokenConverter();
    }
  }
}