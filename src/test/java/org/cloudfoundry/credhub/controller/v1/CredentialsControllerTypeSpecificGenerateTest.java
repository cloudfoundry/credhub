package org.cloudfoundry.credhub.controller.v1;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.credential.CryptSaltFactory;
import org.cloudfoundry.credhub.credential.RsaCredentialValue;
import org.cloudfoundry.credhub.credential.SshCredentialValue;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.credential.UserCredentialValue;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.domain.RsaCredentialVersion;
import org.cloudfoundry.credhub.domain.SshCredentialVersion;
import org.cloudfoundry.credhub.domain.UserCredentialVersion;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.generator.CertificateGenerator;
import org.cloudfoundry.credhub.generator.PasswordCredentialGenerator;
import org.cloudfoundry.credhub.generator.RsaGenerator;
import org.cloudfoundry.credhub.generator.SshGenerator;
import org.cloudfoundry.credhub.generator.UserGenerator;
import org.cloudfoundry.credhub.helper.AuditingHelper;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.cloudfoundry.credhub.repository.EventAuditRecordRepository;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.cloudfoundry.credhub.request.DefaultCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.GenerationParameters;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.view.PermissionsView;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.rules.SpringClassRule;
import org.springframework.test.context.junit4.rules.SpringMethodRule;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.UUID;
import java.util.function.Consumer;

import static com.google.common.collect.Lists.newArrayList;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.ACL_UPDATE;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static org.cloudfoundry.credhub.helper.TestHelper.mockOutCurrentTimeProvider;
import static org.cloudfoundry.credhub.request.PermissionOperation.DELETE;
import static org.cloudfoundry.credhub.request.PermissionOperation.READ;
import static org.cloudfoundry.credhub.request.PermissionOperation.READ_ACL;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE_ACL;
import static org.cloudfoundry.credhub.util.MultiJsonPathMatcher.multiJsonPath;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Parameterized.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialsControllerTypeSpecificGenerateTest {
  @ClassRule
  public static final SpringClassRule SPRING_CLASS_RULE = new SpringClassRule();

  @Rule
  public final SpringMethodRule springMethodRule = new SpringMethodRule();

  private static final String FAKE_PASSWORD = "generated-credential";
  private static final String USERNAME = "generated-user";
  private static final String PUBLIC_KEY = "public_key";
  private static final String CERTIFICATE = "certificate";
  private static final String CA = "ca";
  private static final String PRIVATE_KEY = "private_key";
  private static final String CREDENTIAL_NAME = "/my-namespace/subTree/credential-name";
  private static final Instant FROZEN_TIME = Instant.ofEpochSecond(1400011001L);

  private static UUID credentialUuid;

  @Autowired
  private WebApplicationContext webApplicationContext;

  @SpyBean
  private CredentialVersionDataService credentialVersionDataService;

  @MockBean
  private CurrentTimeProvider mockCurrentTimeProvider;

  @MockBean
  private PasswordCredentialGenerator passwordGenerator;

  @MockBean
  private CertificateGenerator certificateGenerator;

  @MockBean
  private SshGenerator sshGenerator;

  @MockBean
  private RsaGenerator rsaGenerator;

  @MockBean
  private UserGenerator userGenerator;

  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  @SpyBean
  private ObjectMapper objectMapper;

  @Autowired
  private Encryptor encryptor;

  @Autowired
  private CryptSaltFactory cryptSaltFactory;

  private AuditingHelper auditingHelper;
  private MockMvc mockMvc;

  @Parameterized.Parameter
  public TestParameterizer parametizer;

  @Parameterized.Parameters(name = "{0}")
  public static Collection<Object> parameters() {
    credentialUuid = UUID.randomUUID();
    Collection<Object> params = new ArrayList<>();

    TestParameterizer passwordParameters = new TestParameterizer("password", "{\"exclude_number\": true}") {
      ResultMatcher jsonAssertions() {
        return multiJsonPath("$.value", FAKE_PASSWORD);
      }

      void credentialAssertions(CredentialVersion credential) {
        PasswordCredentialVersion passwordCredential = (PasswordCredentialVersion) credential;
        assertThat(passwordCredential.getGenerationParameters().isExcludeNumber(), equalTo(true));
        assertThat(passwordCredential.getPassword(), equalTo(FAKE_PASSWORD));
      }

      CredentialVersion createCredential(Encryptor encryptor) {
        return new PasswordCredentialVersion(CREDENTIAL_NAME)
            .setEncryptor(encryptor)
            .setPasswordAndGenerationParameters(FAKE_PASSWORD, new StringGenerationParameters().setExcludeNumber(true))
            .setUuid(credentialUuid)
            .setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));
      }
    };

    TestParameterizer userParameterizer = new TestParameterizer("user", "null") {
      ResultMatcher jsonAssertions() {
        return multiJsonPath(
            "$.value.username", USERNAME,
            "$.value.password", FAKE_PASSWORD
        );
      }

      void credentialAssertions(CredentialVersion credential) {
        UserCredentialVersion userCredential = (UserCredentialVersion) credential;
        assertThat(userCredential.getUsername(), equalTo(USERNAME));
        assertThat(userCredential.getPassword(), equalTo(FAKE_PASSWORD));
      }

      CredentialVersion createCredential(Encryptor encryptor) {
        return new UserCredentialVersion(CREDENTIAL_NAME)
            .setEncryptor(encryptor)
            .setPassword(FAKE_PASSWORD)
            .setUsername(USERNAME)
            .setUuid(credentialUuid)
            .setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));
      }
    };

    TestParameterizer certificateParameterizer = new TestParameterizer("certificate", "{\"common_name\":\"my-common-name\",\"self_sign\":true}") {
      ResultMatcher jsonAssertions() {
        return multiJsonPath(
            "$.value.certificate", "certificate",
            "$.value.private_key", "private_key",
            "$.value.ca", "ca");
      }

      void credentialAssertions(CredentialVersion credential) {
        CertificateCredentialVersion certificateCredential = (CertificateCredentialVersion) credential;
        assertThat(certificateCredential.getCa(), equalTo(CA));
        assertThat(certificateCredential.getCertificate(), equalTo(CERTIFICATE));
        assertThat(certificateCredential.getPrivateKey(), equalTo(PRIVATE_KEY));
      }

      CredentialVersion createCredential(Encryptor encryptor) {
        return new CertificateCredentialVersion(CREDENTIAL_NAME)
            .setEncryptor(encryptor)
            .setCa(CA)
            .setCertificate(CERTIFICATE)
            .setPrivateKey(PRIVATE_KEY)
            .setUuid(credentialUuid)
            .setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));
      }
    };

    TestParameterizer sshParameterizer = new TestParameterizer("ssh", "null") {
      ResultMatcher jsonAssertions() {
        return multiJsonPath(
            "$.value.public_key", "public_key",
            "$.value.private_key", "private_key",
            "$.value.public_key_fingerprint", null);
      }

      void credentialAssertions(CredentialVersion credential) {
        SshCredentialVersion sshCredential = (SshCredentialVersion) credential;
        assertThat(sshCredential.getPublicKey(), equalTo(PUBLIC_KEY));
        assertThat(sshCredential.getPrivateKey(), equalTo(PRIVATE_KEY));
      }

      CredentialVersion createCredential(Encryptor encryptor) {
        return new SshCredentialVersion(CREDENTIAL_NAME)
            .setEncryptor(encryptor)
            .setPrivateKey(PRIVATE_KEY)
            .setPublicKey(PUBLIC_KEY)
            .setUuid(credentialUuid)
            .setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));
      }
    };

    TestParameterizer rsaParameterizer = new TestParameterizer("rsa", "null") {
      ResultMatcher jsonAssertions() {
        return multiJsonPath("$.value.public_key", "public_key",
            "$.value.private_key", "private_key");
      }

      void credentialAssertions(CredentialVersion credential) {
        RsaCredentialVersion rsaCredential = (RsaCredentialVersion) credential;
        assertThat(rsaCredential.getPublicKey(), equalTo(PUBLIC_KEY));
        assertThat(rsaCredential.getPrivateKey(), equalTo(PRIVATE_KEY));
      }

      CredentialVersion createCredential(Encryptor encryptor) {
        return new RsaCredentialVersion(CREDENTIAL_NAME)
            .setEncryptor(encryptor)
            .setPrivateKey(PRIVATE_KEY)
            .setPublicKey(PUBLIC_KEY)
            .setUuid(credentialUuid)
            .setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));
      }
    };

    params.add(passwordParameters);
    params.add(userParameterizer);
    params.add(certificateParameterizer);
    params.add(sshParameterizer);
    params.add(rsaParameterizer);

    return params;
  }

  @Before
  public void setup() throws Exception {
    String fakeSalt = cryptSaltFactory.generateSalt(FAKE_PASSWORD);
    Consumer<Long> fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

    fakeTimeSetter.accept(FROZEN_TIME.toEpochMilli());
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    when(passwordGenerator.generateCredential(any(GenerationParameters.class)))
        .thenReturn(new StringCredentialValue(FAKE_PASSWORD));

    when(certificateGenerator.generateCredential(any(GenerationParameters.class)))
        .thenReturn(new CertificateCredentialValue(CA, CERTIFICATE, PRIVATE_KEY, null));

    when(sshGenerator.generateCredential(any(GenerationParameters.class)))
        .thenReturn(new SshCredentialValue(PUBLIC_KEY, PRIVATE_KEY, null));

    when(rsaGenerator.generateCredential(any(GenerationParameters.class)))
        .thenReturn(new RsaCredentialValue(PUBLIC_KEY, PRIVATE_KEY));

    when(userGenerator.generateCredential(any(GenerationParameters.class)))
        .thenReturn(new UserCredentialValue(USERNAME, FAKE_PASSWORD, fakeSalt));

    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
  }


  @Test
  public void generatingACredential_validatesTheRequestBody() throws Exception {
    MockHttpServletRequestBuilder request = createGenerateNewCredentialRequest();

    DefaultCredentialGenerateRequest requestBody = mock(DefaultCredentialGenerateRequest.class);

    Mockito.doThrow(new ParameterizedValidationException("error.bad_request")).when(requestBody).validate();
    doReturn(requestBody).when(objectMapper).readValue(anyString(), any(Class.class));

    mockMvc.perform(request)
        .andExpect(status().isBadRequest())
        .andExpect(content().json("{\"error\":\"The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.\"}"));
  }

  @Test
  public void shouldAcceptAnyCasingForType() throws Exception {
    MockHttpServletRequestBuilder request = post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\":\"" + CREDENTIAL_NAME + "\"," +
            "\"type\":\"" + parametizer.credentialType.toUpperCase() + "\"," +
            "\"parameters\":" + parametizer.generationParameters + "," +
            "\"overwrite\":" + false +
            "}");

    mockMvc.perform(request)
        .andExpect(status().isOk())
        .andExpect(parametizer.jsonAssertions())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(multiJsonPath(
            "$.type", parametizer.credentialType,
            "$.version_created_at", FROZEN_TIME.toString())
        );
  }

  @Test
  public void generatingANewCredential_shouldReturnGeneratedCredentialAndAskDataServiceToPersistTheCredential() throws Exception {
    MockHttpServletRequestBuilder request = createGenerateNewCredentialRequest();

    ResultActions response = mockMvc.perform(request);

    ArgumentCaptor<CredentialVersion> argumentCaptor = ArgumentCaptor.forClass(CredentialVersion.class);
    verify(credentialVersionDataService, times(1)).save(argumentCaptor.capture());

    response
        .andExpect(parametizer.jsonAssertions())
        .andExpect(multiJsonPath(
            "$.type", parametizer.credentialType,
            "$.id", argumentCaptor.getValue().getUuid().toString(),
            "$.version_created_at", FROZEN_TIME.toString()))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON));
  }

  @Test
  public void generatingANewCredential_persistsAnAuditEntry() throws Exception {
    MockHttpServletRequestBuilder request = createGenerateNewCredentialRequest();

    mockMvc.perform(request);

    auditingHelper.verifyAuditing(AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/data", 200, newArrayList(
        new EventAuditRecordParameters(CREDENTIAL_UPDATE, CREDENTIAL_NAME),
        new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, READ, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
        new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, WRITE, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
        new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, DELETE, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
        new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, READ_ACL, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
        new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, WRITE_ACL, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID)
    ));
  }

  @Test
  public void generatingANewCredential_addsFullPermissionsForCurrentUser() throws Exception {
    MockHttpServletRequestBuilder request = createGenerateNewCredentialRequest();

    mockMvc.perform(request);

    MockHttpServletRequestBuilder getRequest = get("/api/v1/permissions?credential_name=" + CREDENTIAL_NAME)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    MvcResult result = mockMvc.perform(getRequest)
        .andExpect(status().isOk())
        .andReturn();
    String content = result.getResponse().getContentAsString();
    PermissionsView acl = JsonTestHelper
        .deserialize(content, PermissionsView.class);

    assertThat(acl.getCredentialName(), equalTo(CREDENTIAL_NAME));
    assertThat(acl.getPermissions(), Matchers.contains(
        samePropertyValuesAs(
            new PermissionEntry(AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
                asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL)))));
  }

  @Test
  public void generatingANewCredentialVersion_withOverwrite_shouldGenerateANewCredential() throws Exception {
    beforeEachExistingCredential();
    MockHttpServletRequestBuilder request = beforeEachOverwriteSetToTrue();

    ResultActions response = mockMvc.perform(request);

    ArgumentCaptor<CredentialVersion> argumentCaptor = ArgumentCaptor.forClass(CredentialVersion.class);
    verify(credentialVersionDataService, times(1)).save(argumentCaptor.capture());

    response
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(parametizer.jsonAssertions())
        .andExpect(multiJsonPath(
            "$.type", parametizer.credentialType,
            "$.id", argumentCaptor.getValue().getUuid().toString(),
            "$.version_created_at", FROZEN_TIME.toString()));
  }

  @Test
  public void generatingANewCredentialVersion_withOverwrite_shouldPersistTheNewCredential() throws Exception {
    beforeEachExistingCredential();
    MockHttpServletRequestBuilder request = beforeEachOverwriteSetToTrue();

    mockMvc.perform(request);

    CredentialVersion credentialVersion = credentialVersionDataService.findMostRecent(CREDENTIAL_NAME);
    parametizer.credentialAssertions(credentialVersion);
  }

  @Test
  public void generatingANewCredentialVersion_withOverwrite_shouldPersistAnAuditRecord() throws Exception {
    beforeEachExistingCredential();
    MockHttpServletRequestBuilder request = beforeEachOverwriteSetToTrue();

    mockMvc.perform(request);

    auditingHelper.verifyAuditing(
        CREDENTIAL_UPDATE,
        CREDENTIAL_NAME,
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/data",
        200
    );
  }

  @Test
  public void generatingANewCredentialVersion_withOverwriteFalse_returnsThePreviousVersion() throws Exception {
    beforeEachExistingCredential();
    MockHttpServletRequestBuilder request = beforeEachOverwriteSetToFalse();

    mockMvc.perform(request)
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(parametizer.jsonAssertions())
        .andExpect(multiJsonPath(
            "$.id", credentialUuid.toString(),
            "$.version_created_at", FROZEN_TIME.minusSeconds(1).toString()));
  }

  @Test
  public void generatingANewCredentialVersion_withOverwriteFalse_doesNotPersistANewVersion() throws Exception {
    beforeEachExistingCredential();

    MockHttpServletRequestBuilder request = beforeEachOverwriteSetToFalse();
    mockMvc.perform(request);

    verify(credentialVersionDataService, times(0)).save(any(CredentialVersion.class));
  }

  @Test
  public void generatingANewCredentialVersion_withOverwriteFalse_persistsAnAuditEntry() throws Exception {
    beforeEachExistingCredential();
    MockHttpServletRequestBuilder request = beforeEachOverwriteSetToFalse();

    mockMvc.perform(request);

    auditingHelper.verifyAuditing(CREDENTIAL_ACCESS, CREDENTIAL_NAME, AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/data", 200);
  }

  private MockHttpServletRequestBuilder createGenerateNewCredentialRequest() {
    return post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\":\"" + CREDENTIAL_NAME + "\"," +
            "\"type\":\"" + parametizer.credentialType + "\"," +
            "\"parameters\":" + parametizer.generationParameters + "," +
            "\"overwrite\":" + false +
            "}");
  }

  private void beforeEachExistingCredential() {
    doReturn(parametizer.createCredential(encryptor))
        .when(credentialVersionDataService)
        .findMostRecent(CREDENTIAL_NAME);
  }

  private MockHttpServletRequestBuilder beforeEachOverwriteSetToTrue() throws Exception {
    return post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"" + parametizer.credentialType + "\"," +
            "  \"name\":\"" + CREDENTIAL_NAME + "\"," +
            "  \"parameters\":" + parametizer.generationParameters + "," +
            "  \"overwrite\":true" +
            "}");
  }

  private MockHttpServletRequestBuilder beforeEachOverwriteSetToFalse() throws Exception {
    return post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"" + parametizer.credentialType + "\"," +
            "  \"name\":\"" + CREDENTIAL_NAME + "\"," +
            "  \"parameters\":" + parametizer.generationParameters + "," +
            "  \"overwrite\":false" +
            "}");
  }

  private static abstract class TestParameterizer {
    public final String credentialType;
    public final String generationParameters;

    public TestParameterizer(String credentialType, String generationParameters) {
      this.credentialType = credentialType;
      this.generationParameters = generationParameters;
    }

    @Override
    public String toString() {
      return credentialType;
    }

    abstract ResultMatcher jsonAssertions();

    abstract void credentialAssertions(CredentialVersion credentialVersion);

    abstract CredentialVersion createCredential(Encryptor encryptor);
  }

}
