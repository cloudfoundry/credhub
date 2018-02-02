package org.cloudfoundry.credhub.controller.v1;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.credential.RsaCredentialValue;
import org.cloudfoundry.credhub.credential.SshCredentialValue;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.generator.CertificateGenerator;
import org.cloudfoundry.credhub.generator.PassayStringCredentialGenerator;
import org.cloudfoundry.credhub.generator.RsaGenerator;
import org.cloudfoundry.credhub.generator.SshGenerator;
import org.cloudfoundry.credhub.request.RsaGenerationParameters;
import org.cloudfoundry.credhub.request.SshGenerationParameters;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;

import static org.cloudfoundry.credhub.helper.TestHelper.mockOutCurrentTimeProvider;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialsControllerGenerateTest {

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
  private UserContext userContext;

  @Before
  public void beforeEach() {
    Consumer<Long> fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);
    userContext = mock(UserContext.class);

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
    final MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\"type\":\"foo\",\"name\":\"" + CREDENTIAL_NAME + "\"}");

    String expectedError = "The request does not include a valid type. Valid values for generate include 'password', 'user', 'certificate', 'ssh' and 'rsa'.";

    mockMvc.perform(postRequest)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void generatingACredential_returnsAnErrorForValueType() throws Exception {
    final MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\"type\":\"value\",\"name\":\"" + CREDENTIAL_NAME + "\"}");

    String expectedError = "Credentials of this type cannot be generated. Please adjust the credential type and retry your request.";

    mockMvc.perform(postRequest)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void generatingACredential_returnsAnErrorForJsonType() throws Exception {
    final MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\"type\":\"json\",\"name\":\"" + CREDENTIAL_NAME + "\"}");

    String expectedError = "Credentials of this type cannot be generated. Please adjust the credential type and retry your request.";

    mockMvc.perform(postRequest)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void generatingACredential_whenAnotherThreadWinsARaceToWriteANewValue_retriesAndFindsTheValueWrittenByTheOtherThread() throws Exception {
    final PasswordCredentialVersion expectedCredential = new PasswordCredentialVersion(CREDENTIAL_NAME);
    final UUID uuid = UUID.randomUUID();

    expectedCredential.setEncryptor(encryptor);
    expectedCredential.setPasswordAndGenerationParameters(FAKE_PASSWORD_NAME, null);

    Mockito.reset(credentialVersionDataService);

    doReturn(null)
        .doReturn(expectedCredential
            .setUuid(uuid)
            .setVersionCreatedAt(FROZEN_TIME.minusSeconds(1))
        ).when(credentialVersionDataService).findMostRecent(anyString());

    doThrow(new DataIntegrityViolationException("we already have one of those"))
        .when(credentialVersionDataService).save(any(CredentialVersion.class));

    final MockHttpServletRequestBuilder postRequest = post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\"type\":\"password\",\"name\":\"" + CREDENTIAL_NAME + "\"}");

    ResultActions response = mockMvc.perform(postRequest);

    verify(credentialVersionDataService).save(any(CredentialVersion.class));
    response.andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.type").value("password"))
        .andExpect(jsonPath("$.value").value(FAKE_PASSWORD_NAME))
        .andExpect(jsonPath("$.id").value(uuid.toString()))
        .andExpect(jsonPath("$.version_created_at").value(FROZEN_TIME.minusSeconds(1).toString()));
  }

  @Test
  public void generatingACredential_whenTypeIsNotPresent_returns400() throws Exception {
    String expectedError = "The request does not include a valid type. Valid values for generate include 'password', 'user', 'certificate', 'ssh' and 'rsa'.";

    mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .content("{\"name\":\"some-new-credential-name\"}")
    )
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void generatingACredential_whenNameIsEmpty_throws400() throws Exception {
    String expectedError = "A credential name must be provided. Please validate your input and retry your request.";
    mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .content("{\"type\":\"password\",\"name\":\"\"}")
    )
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void generatingACredential_whenNameIsMissing_throws400() throws Exception {
    String expectedError = "A credential name must be provided. Please validate your input and retry your request.";

    mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .content("{\"type\":\"password\"}")
    )
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void generatingACredential_whenIncorrectParamsAreSent_returns400() throws Exception {
    String expectedError = "The request includes an unrecognized parameter 'some_unknown_param'. Please update or remove this parameter and retry your request.";

    mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
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
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void regeneratingACredential_withEmptyName_returns400() throws Exception {
    String expectedError = "A credential name must be provided. Please validate your input and retry your request.";
    mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        //language=JSON
        .content("{" +
            "\"name\": null," +
            "\"regenerate\": true" +
            "}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").value(expectedError));


  }
}
