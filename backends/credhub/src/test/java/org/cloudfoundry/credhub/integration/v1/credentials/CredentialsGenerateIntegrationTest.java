package org.cloudfoundry.credhub.integration.v1.credentials;

import java.text.MessageFormat;
import java.time.Instant;
import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import org.cloudfoundry.credhub.AuthConstants;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.TestHelper;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.credential.RsaCredentialValue;
import org.cloudfoundry.credhub.credential.SshCredentialValue;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.generators.CertificateGenerator;
import org.cloudfoundry.credhub.generators.PassayStringCredentialGenerator;
import org.cloudfoundry.credhub.generators.RsaGenerator;
import org.cloudfoundry.credhub.generators.SshGenerator;
import org.cloudfoundry.credhub.requests.RsaGenerationParameters;
import org.cloudfoundry.credhub.requests.SshGenerationParameters;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.cloudfoundry.credhub.services.CredentialVersionDataService;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
public class CredentialsGenerateIntegrationTest {

  private static final Instant FROZEN_TIME = Instant.ofEpochSecond(1400011001L);
  private static final String CREDENTIAL_NAME = "/my-namespace/subTree/credential-name";
  private static final String FAKE_PASSWORD_NAME = "generated-credential";
  private static final String PUBLIC_KEY = "public_key";
  private static final String PRIVATE_KEY = "private_key";
  private static final String CERT = "cert";

  @Autowired
  private WebApplicationContext webApplicationContext;

  @SpyBean
  private CredentialVersionDataService credentialVersionDataService;

  @MockBean
  private PassayStringCredentialGenerator credentialGenerator;

  @MockBean
  private SshGenerator sshGenerator;

  @MockBean
  private RsaGenerator rsaGenerator;

  @MockBean
  private CertificateGenerator certificateGenerator;

  @Autowired
  private Encryptor encryptor;

  @MockBean
  private CurrentTimeProvider mockCurrentTimeProvider;

  private MockMvc mockMvc;

  @Before
  public void beforeEach() {
    final Consumer<Long> fakeTimeSetter = TestHelper.mockOutCurrentTimeProvider(mockCurrentTimeProvider);

    fakeTimeSetter.accept(FROZEN_TIME.toEpochMilli());
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();
    when(credentialGenerator.generateCredential(any(StringGenerationParameters.class)))
      .thenReturn(new StringCredentialValue(FAKE_PASSWORD_NAME));

    when(sshGenerator.generateCredential(any(SshGenerationParameters.class)))
      .thenReturn(new SshCredentialValue(PUBLIC_KEY, PRIVATE_KEY, null));

    when(rsaGenerator.generateCredential(any(RsaGenerationParameters.class)))
      .thenReturn(new RsaCredentialValue(PUBLIC_KEY, PRIVATE_KEY));

    when(certificateGenerator.generateCredential(any(CertificateGenerationParameters.class)))
      .thenReturn(new CertificateCredentialValue("ca_cert", CERT, PRIVATE_KEY, null));
  }

  @Test
  public void generatingACredential_returnsAnErrorMessageForUnknownType() throws Exception {
    String message = MessageFormat.format(ErrorMessages.INVALID_TYPE_WITH_GENERATE_PROMPT, new Object[0]);

    final MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{\"type\":\"foo\",\"name\":\"" + CREDENTIAL_NAME + "\"}");

    mockMvc.perform(postRequest)
      .andExpect(status().isBadRequest())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(message));
  }

  @Test
  public void generatingACredential_returnsAnErrorForValueType() throws Exception {
    final MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{\"type\":\"value\",\"name\":\"" + CREDENTIAL_NAME + "\"}");

    mockMvc.perform(postRequest)
      .andExpect(status().isBadRequest())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(ErrorMessages.CANNOT_GENERATE_TYPE));
  }

  @Test
  public void generatingACredential_returnsAnErrorForJsonType() throws Exception {
    final MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{\"type\":\"json\",\"name\":\"" + CREDENTIAL_NAME + "\"}");

    mockMvc.perform(postRequest)
      .andExpect(status().isBadRequest())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(ErrorMessages.CANNOT_GENERATE_TYPE));
  }

  @Test
  public void generatingACredential_whenTypeIsNotPresent_returns400() throws Exception {
    String message = MessageFormat.format(ErrorMessages.INVALID_TYPE_WITH_GENERATE_PROMPT, new Object[0]);

    mockMvc.perform(post("/api/v1/data")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .content("{\"name\":\"some-new-credential-name\"}")
    )
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value(message));
  }

  @Test
  public void generatingACredential_whenNameIsEmpty_throws400() throws Exception {
    mockMvc.perform(post("/api/v1/data")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .content("{\"type\":\"password\",\"name\":\"\"}")
    )
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value(ErrorMessages.MISSING_NAME));
  }

  @Test
  public void generatingACredential_whenNameIsMissing_throws400() throws Exception {
    mockMvc.perform(post("/api/v1/data")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .content("{\"type\":\"password\"}")
    )
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value(ErrorMessages.MISSING_NAME));
  }

  @Test
  public void generatingACredential_whenIncorrectParamsAreSent_returns400() throws Exception {
    final String message = MessageFormat.format(ErrorMessages.INVALID_JSON_KEY, "some_unknown_param");

    mockMvc.perform(post("/api/v1/data")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      //language=JSON
      .content("{" +
        "\"type\":\"password\"," +
        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
        "\"parameters\":{" +
        "\"exclude_number\": true" +
        "}," +
        "\"some_unknown_param\": false" +
        "}")
    )
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value(message));
  }

  @Test
  public void generatingACertificate_withoutParameters_returns400() throws Exception {
    final MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "\"type\":\"certificate\"," +
        "\"name\":\"" + CREDENTIAL_NAME + "\"" +
        "}");

    String message = MessageFormat.format(ErrorMessages.NO_CERTIFICATE_PARAMETERS, new Object[0]);
    mockMvc.perform(postRequest)
      .andExpect(status().isBadRequest())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(message));
  }

  @Test
  public void regeneratingACredential_withEmptyName_returns400() throws Exception {
    mockMvc.perform(post("/api/v1/data")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      //language=JSON
      .content("{" +
        "\"name\": null," +
        "\"regenerate\": true" +
        "}"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value(ErrorMessages.MISSING_NAME));
  }
}
