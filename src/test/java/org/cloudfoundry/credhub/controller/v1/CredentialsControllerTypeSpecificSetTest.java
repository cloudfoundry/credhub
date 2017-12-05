package org.cloudfoundry.credhub.controller.v1;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.JsonCredentialVersion;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.domain.RsaCredentialVersion;
import org.cloudfoundry.credhub.domain.SshCredentialVersion;
import org.cloudfoundry.credhub.domain.UserCredentialVersion;
import org.cloudfoundry.credhub.domain.ValueCredentialVersion;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.handler.SetHandler;
import org.cloudfoundry.credhub.helper.AuditingHelper;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.cloudfoundry.credhub.repository.EventAuditRecordRepository;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.cloudfoundry.credhub.request.BaseCredentialSetRequest;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.view.PermissionsView;
import net.minidev.json.JSONObject;
import org.cloudfoundry.credhub.util.TestConstants;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.rules.SpringClassRule;
import org.springframework.test.context.junit4.rules.SpringMethodRule;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.io.InputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
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
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.cloudfoundry.credhub.util.MultiJsonPathMatcher.multiJsonPath;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Parameterized.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialsControllerTypeSpecificSetTest {
  @ClassRule
  public static final SpringClassRule SPRING_CLASS_RULE = new SpringClassRule();

  @Rule
  public final SpringMethodRule springMethodRule = new SpringMethodRule();

  private static final Instant FROZEN_TIME = Instant.ofEpochSecond(1400011001L);

  private static final String CREDENTIAL_NAME = "/my-namespace/subTree/credential-name";

  private static final ImmutableMap<String, Integer> nestedValue = ImmutableMap.<String, Integer>builder()
      .put("num", 10)
      .build();
  private static final ImmutableMap<String, Object> jsonValueMap = ImmutableMap.<String, Object>builder()
      .put("key", "value")
      .put("fancy", nestedValue)
      .put("array", Arrays.asList("foo", "bar"))
      .build();

  private static final String VALUE_VALUE = "test-value";
  private static final String PASSWORD_VALUE = "test-password";
  private static final String CERTIFICATE_VALUE_JSON_STRING = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
          .put("ca", TestConstants.TEST_CA)
          .put("certificate", TestConstants.TEST_CERTIFICATE)
          .put("private_key", TestConstants.TEST_PRIVATE_KEY)
          .build());
  private static final String SSH_VALUE_JSON_STRING = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
          .put("public_key", TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT)
          .put("private_key", TestConstants.PRIVATE_KEY_4096)
          .build());
  private static final String RSA_VALUE_JSON_STRING = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
          .put("public_key", TestConstants.RSA_PUBLIC_KEY_4096)
          .put("private_key", TestConstants.PRIVATE_KEY_4096)
          .build());
  private static final String JSON_VALUE_JSON_STRING = JSONObject.toJSONString(jsonValueMap);
  private static final String USERNAME_VALUE = "test-username";
  private static final String USER_VALUE_JSON_STRING = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
          .put("username", USERNAME_VALUE)
          .put("password", PASSWORD_VALUE)
          .build());

  @Autowired
  private WebApplicationContext webApplicationContext;

  @SpyBean
  private CredentialVersionDataService credentialVersionDataService;

  @SpyBean
  private SetHandler setHandler;

  @MockBean
  private CurrentTimeProvider mockCurrentTimeProvider;

  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  @SpyBean
  private ObjectMapper objectMapper;

  @Autowired
  private Encryptor encryptor;

  private AuditingHelper auditingHelper;
  private MockMvc mockMvc;

  @Parameterized.Parameter
  public TestParametizer parametizer;

  @Parameterized.Parameters(name = "{0}")
  public static Collection<Object> parameters() {
    UUID credentialUuid = UUID.randomUUID();

    Collection<Object> params = new ArrayList<>();

    TestParametizer valueParameters = new TestParametizer("value", "\"" + VALUE_VALUE + "\"") {
      ResultMatcher jsonAssertions() {
        return multiJsonPath("$.value", VALUE_VALUE);
      }

      void credentialAssertions(CredentialVersion credential) {
        assertThat(((ValueCredentialVersion) credential).getValue(), equalTo(VALUE_VALUE));
      }

      CredentialVersion createCredential(Encryptor encryptor) {
        return new ValueCredentialVersion(CREDENTIAL_NAME)
            .setEncryptor(encryptor)
            .setValue(VALUE_VALUE)
            .setUuid(credentialUuid)
            .setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));
      }
    };
    TestParametizer passwordParameters = new TestParametizer("password", "\"" + PASSWORD_VALUE + "\"") {
      ResultMatcher jsonAssertions() {
        return multiJsonPath("$.value", PASSWORD_VALUE);
      }

      void credentialAssertions(CredentialVersion credential) {
        assertThat(((PasswordCredentialVersion) credential).getPassword(), equalTo(PASSWORD_VALUE));
      }

      CredentialVersion createCredential(Encryptor encryptor) {
        return new PasswordCredentialVersion(CREDENTIAL_NAME)
            .setEncryptor(encryptor)
            .setPasswordAndGenerationParameters(PASSWORD_VALUE, null)
            .setUuid(credentialUuid)
            .setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));
      }
    };
    TestParametizer certificateParameters = new TestParametizer("certificate", CERTIFICATE_VALUE_JSON_STRING) {
      ResultMatcher jsonAssertions() {
        return multiJsonPath(
            "$.value.certificate", TestConstants.TEST_CERTIFICATE,
            "$.value.private_key", TestConstants.TEST_PRIVATE_KEY,
            "$.value.ca", TestConstants.TEST_CA
        );
      }

      void credentialAssertions(CredentialVersion credential) {
        CertificateCredentialVersion certificateCredential = (CertificateCredentialVersion) credential;
        assertThat(certificateCredential.getCa(), equalTo(TestConstants.TEST_CA));
        assertThat(certificateCredential.getCertificate(), equalTo(TestConstants.TEST_CERTIFICATE));
        assertThat(certificateCredential.getPrivateKey(), equalTo(TestConstants.TEST_PRIVATE_KEY));
      }

      CredentialVersion createCredential(Encryptor encryptor) {
        return new CertificateCredentialVersion(CREDENTIAL_NAME)
            .setEncryptor(encryptor)
            .setCa(TestConstants.TEST_CA)
            .setCertificate(TestConstants.TEST_CERTIFICATE)
            .setPrivateKey(TestConstants.TEST_PRIVATE_KEY)
            .setUuid(credentialUuid)
            .setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));
      }
    };
    TestParametizer sshParameters = new TestParametizer("ssh", SSH_VALUE_JSON_STRING) {
      ResultMatcher jsonAssertions() {
        return multiJsonPath(
            "$.value.public_key", TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT,
            "$.value.private_key", TestConstants.PRIVATE_KEY_4096,
            "$.value.public_key_fingerprint", "UmqxK9UJJR4Jrcw0DcwqJlCgkeQoKp8a+HY+0p0nOgc"
        );
      }

      void credentialAssertions(CredentialVersion credential) {
        SshCredentialVersion sshCredential = (SshCredentialVersion) credential;
        assertThat(sshCredential.getPublicKey(), equalTo(TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT));
        assertThat(sshCredential.getPrivateKey(), equalTo(TestConstants.PRIVATE_KEY_4096));
      }

      CredentialVersion createCredential(Encryptor encryptor) {
        return new SshCredentialVersion(CREDENTIAL_NAME)
            .setEncryptor(encryptor)
            .setPrivateKey(TestConstants.PRIVATE_KEY_4096)
            .setPublicKey(TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT)
            .setUuid(credentialUuid)
            .setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));
      }
    };
    TestParametizer rsaParameters = new TestParametizer("rsa", RSA_VALUE_JSON_STRING) {
      ResultMatcher jsonAssertions() {
        return multiJsonPath(
            "$.value.public_key", TestConstants.RSA_PUBLIC_KEY_4096,
            "$.value.private_key", TestConstants.PRIVATE_KEY_4096
        );
      }

      void credentialAssertions(CredentialVersion credential) {
        RsaCredentialVersion rsaCredential = (RsaCredentialVersion) credential;
        assertThat(rsaCredential.getPublicKey(), equalTo(TestConstants.RSA_PUBLIC_KEY_4096));
        assertThat(rsaCredential.getPrivateKey(), equalTo(TestConstants.PRIVATE_KEY_4096));
      }

      CredentialVersion createCredential(Encryptor encryptor) {
        return new RsaCredentialVersion(CREDENTIAL_NAME)
            .setEncryptor(encryptor)
            .setPrivateKey(TestConstants.PRIVATE_KEY_4096)
            .setPublicKey(TestConstants.RSA_PUBLIC_KEY_4096)
            .setUuid(credentialUuid)
            .setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));
      }
    };
    TestParametizer jsonParameters = new TestParametizer("json", JSON_VALUE_JSON_STRING) {
      ResultMatcher jsonAssertions() {
        return multiJsonPath("$.value", jsonValueMap);
      }

      void credentialAssertions(CredentialVersion credential) {
        JsonCredentialVersion jsonCredential = (JsonCredentialVersion) credential;
        assertThat(jsonCredential.getValue(), equalTo(jsonValueMap));
      }

      CredentialVersion createCredential(Encryptor encryptor) {
        return new JsonCredentialVersion(CREDENTIAL_NAME)
            .setEncryptor(encryptor)
            .setValue(jsonValueMap)
            .setUuid(credentialUuid)
            .setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));
      }
    };
    TestParametizer userParameters = new TestParametizer("user", USER_VALUE_JSON_STRING) {
      ResultMatcher jsonAssertions() {
        return multiJsonPath(
            "$.value.username", USERNAME_VALUE,
            "$.value.password", PASSWORD_VALUE
        );
      }

      void credentialAssertions(CredentialVersion credential) {
        UserCredentialVersion userCredential = (UserCredentialVersion) credential;
        assertThat(userCredential.getUsername(), equalTo(USERNAME_VALUE));
        assertThat(userCredential.getPassword(), equalTo(PASSWORD_VALUE));
      }

      CredentialVersion createCredential(Encryptor encryptor) {
        return new UserCredentialVersion(CREDENTIAL_NAME)
            .setEncryptor(encryptor)
            .setUsername(USERNAME_VALUE)
            .setPassword(PASSWORD_VALUE)
            .setUuid(credentialUuid)
            .setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));
      }
    };

    params.add(valueParameters);
    params.add(passwordParameters);
    params.add(certificateParameters);
    params.add(sshParameters);
    params.add(rsaParameters);
    params.add(jsonParameters);
    params.add(userParameters);

    return params;
  }

  @Before
  public void setUp() throws Exception {
    Consumer<Long> fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

    fakeTimeSetter.accept(FROZEN_TIME.toEpochMilli());
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
  }

  @Test
  public void settingACredential_shouldAcceptAnyCasingForType() throws Exception {
    MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\":\"" + CREDENTIAL_NAME + "\"," +
            "\"type\":\"" + parametizer.credentialType.toUpperCase() + "\"," +
            "\"value\":" + parametizer.credentialValue + "," +
            "\"overwrite\":" + false + "," +
            "\"additional_permissions\": [" +
            "{\"actor\": \"app1-guid\"," +
            "\"operations\": [\"read\"]}]" +
            "}");

    ResultActions response = mockMvc.perform(request);

    ArgumentCaptor<CredentialVersion> argumentCaptor = ArgumentCaptor.forClass(CredentialVersion.class);
    verify(credentialVersionDataService, times(1)).save(argumentCaptor.capture());

    response
        .andExpect(status().isOk())
        .andExpect(parametizer.jsonAssertions())
        .andExpect(multiJsonPath(
            "$.type", parametizer.credentialType,
            "$.id", argumentCaptor.getValue().getUuid().toString(),
            "$.version_created_at", FROZEN_TIME.toString()))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON));
  }

  @Test
  public void settingACredential_returnsTheExpectedResponse() throws Exception {
    MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\":\"" + CREDENTIAL_NAME + "\"," +
            "\"type\":\"" + parametizer.credentialType + "\"," +
            "\"value\":" + parametizer.credentialValue + "," +
            "\"overwrite\":" + false + "," +
            "\"additional_permissions\": [" +
            "{\"actor\": \"app1-guid\"," +
            "\"operations\": [\"read\"]}]" +
            "}");

    ResultActions response = mockMvc.perform(request);

    ArgumentCaptor<CredentialVersion> argumentCaptor = ArgumentCaptor.forClass(CredentialVersion.class);
    verify(credentialVersionDataService, times(1)).save(argumentCaptor.capture());

    response.andExpect(parametizer.jsonAssertions())
        .andExpect(multiJsonPath(
            "$.type", parametizer.credentialType,
            "$.id", argumentCaptor.getValue().getUuid().toString(),
            "$.version_created_at", FROZEN_TIME.toString()))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON));
  }

  @Test
  public void settingACredential_expectsDataServiceToPersistTheCredential() throws Exception {
    MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\":\"" + CREDENTIAL_NAME + "\"," +
            "\"type\":\"" + parametizer.credentialType + "\"," +
            "\"value\":" + parametizer.credentialValue + "," +
            "\"overwrite\":" + false + "," +
            "\"additional_permissions\": [" +
            "{\"actor\": \"app1-guid\"," +
            "\"operations\": [\"read\"]}]" +
            "}");
    ArgumentCaptor<CredentialVersion> argumentCaptor = ArgumentCaptor.forClass(CredentialVersion.class);

    mockMvc.perform(request);

    verify(setHandler, times(1))
        .handle(isA(BaseCredentialSetRequest.class), any());
    verify(credentialVersionDataService, times(1)).save(argumentCaptor.capture());

    CredentialVersion newCredentialVersion = argumentCaptor.getValue();

    parametizer.credentialAssertions(newCredentialVersion);
  }

  @Test
  public void settingACredential_persistsAnAuditEntry() throws Exception {
    MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\":\"" + CREDENTIAL_NAME + "\"," +
            "\"type\":\"" + parametizer.credentialType + "\"," +
            "\"value\":" + parametizer.credentialValue + "," +
            "\"overwrite\":" + false + "," +
            "\"additional_permissions\": [" +
            "{\"actor\": \"app1-guid\"," +
            "\"operations\": [\"read\"]}]" +
            "}");

    mockMvc.perform(request);

    auditingHelper.verifyAuditing(UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/data", 200, newArrayList(
        new EventAuditRecordParameters(CREDENTIAL_UPDATE, CREDENTIAL_NAME),
        new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, READ, "app1-guid"),
        new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, READ, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
        new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, WRITE, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
        new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, DELETE, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
        new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, READ_ACL, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID),
        new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, WRITE_ACL, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID)
    ));
  }

  @Test
  public void creatingACredential_createsRequestedPermissions_andFullPermissionsForCurrentUser() throws Exception {
    MockHttpServletRequestBuilder putRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\":\"" + CREDENTIAL_NAME + "\"," +
            "\"type\":\"" + parametizer.credentialType + "\"," +
            "\"value\":" + parametizer.credentialValue + "," +
            "\"overwrite\":" + false + "," +
            "\"additional_permissions\": [" +
            "{\"actor\": \"app1-guid\"," +
            "\"operations\": [\"read\"]}]" +
            "}");
    MockHttpServletRequestBuilder getRequest = get("/api/v1/permissions?credential_name=" + CREDENTIAL_NAME)
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    mockMvc.perform(putRequest).andExpect(status().isOk());

    String responseContent = mockMvc.perform(getRequest)
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();
    PermissionsView acl = JsonTestHelper.deserialize(responseContent, PermissionsView.class);

    assertThat(acl.getCredentialName(), equalTo(CREDENTIAL_NAME));
    assertThat(acl.getPermissions(), containsInAnyOrder(
        samePropertyValuesAs(
            new PermissionEntry(UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
                asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
        samePropertyValuesAs(
            new PermissionEntry("app1-guid",
                asList(READ)))));
  }

  @Test
  public void validationExceptionsAreReturnedAsErrorMessages() throws Exception {
    MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\":\"" + CREDENTIAL_NAME + "\"," +
            "\"type\":\"" + parametizer.credentialType + "\"," +
            "\"value\":" + parametizer.credentialValue + "," +
            "\"overwrite\":" + false + "," +
            "\"additional_permissions\": [" +
            "{\"actor\": \"app1-guid\"," +
            "\"operations\": [\"read\"]}]" +
            "}");

    BaseCredentialSetRequest requestObject = mock(BaseCredentialSetRequest.class);
    doThrow(new ParameterizedValidationException("error.bad_request")).when(requestObject).validate();
    doReturn(requestObject).when(objectMapper).readValue(any(InputStream.class), any(JavaType.class));

    mockMvc.perform(request)
        .andExpect(status().isBadRequest())
        .andExpect(content().json("{\"error\":\"The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.\"}"));
  }

  @Test
  public void updatingACredential_withTheOverwriteFlagSetToTrue_returnsTheExistingCredentialVersion() throws Exception {
    doReturn(parametizer.createCredential(encryptor)).when(credentialVersionDataService).findMostRecent(CREDENTIAL_NAME);

    final MockHttpServletRequestBuilder put = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"" + parametizer.credentialType + "\"," +
            "  \"name\":\"" + CREDENTIAL_NAME + "\"," +
            "  \"value\":" + parametizer.credentialValue + "," +
            "  \"overwrite\":true" +
            "}");

    ResultActions response = mockMvc.perform(put);

    ArgumentCaptor<CredentialVersion> argumentCaptor = ArgumentCaptor.forClass(CredentialVersion.class);
    verify(credentialVersionDataService, times(1)).save(argumentCaptor.capture());

    response.andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(parametizer.jsonAssertions())
        .andExpect(multiJsonPath(
            "$.type", parametizer.credentialType,
            "$.id", argumentCaptor.getValue().getUuid().toString(),
            "$.version_created_at", FROZEN_TIME.toString()));
  }

  @Test
  public void updatingACredential_withTheOverwriteFlagSetToTrue_persistsTheCredential() throws Exception {
    doReturn(parametizer.createCredential(encryptor)).when(credentialVersionDataService).findMostRecent(CREDENTIAL_NAME);

    final MockHttpServletRequestBuilder put = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"" + parametizer.credentialType + "\"," +
            "  \"name\":\"" + CREDENTIAL_NAME + "\"," +
            "  \"value\":" + parametizer.credentialValue + "," +
            "  \"overwrite\":true" +
            "}");

    mockMvc.perform(put);

    CredentialVersion credentialVersion = credentialVersionDataService.findMostRecent(CREDENTIAL_NAME);
    parametizer.credentialAssertions(credentialVersion);
  }

  @Test
  public void updatingACredential_withTheOverwriteFlagSetToTrue_persistsAnAuditEntry() throws Exception {
    doReturn(parametizer.createCredential(encryptor)).when(credentialVersionDataService).findMostRecent(CREDENTIAL_NAME);

    final MockHttpServletRequestBuilder put = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"" + parametizer.credentialType + "\"," +
            "  \"name\":\"" + CREDENTIAL_NAME + "\"," +
            "  \"value\":" + parametizer.credentialValue + "," +
            "  \"overwrite\":true" +
            "}");

    mockMvc.perform(put);

    auditingHelper.verifyAuditing(CREDENTIAL_UPDATE, CREDENTIAL_NAME, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/data", 200);
  }

  @Test
  public void updatingACredential_withOverwriteSetToFalse_returnsThePreviousVersion() throws Exception {
    CredentialVersion expectedCredentialVersion = parametizer.createCredential(encryptor);
    doReturn(expectedCredentialVersion)
        .when(credentialVersionDataService)
        .findMostRecent(CREDENTIAL_NAME);
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "\"type\":\"" + parametizer.credentialType + "\","
            + "\"name\":\"" + CREDENTIAL_NAME + "\","
            + "\"value\":" + parametizer.credentialValue
            + "}");

    mockMvc.perform(request)
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(parametizer.jsonAssertions())
        .andExpect(multiJsonPath(
            "$.id", expectedCredentialVersion.getUuid().toString(),
            "$.version_created_at", FROZEN_TIME.minusSeconds(1).toString()));
  }

  @Test
  public void updatingACredential_withOverwriteSetToFalse_doesNotPersistTheCredential() throws Exception {
    CredentialVersion expectedCredentialVersion = parametizer.createCredential(encryptor);
    doReturn(expectedCredentialVersion)
        .when(credentialVersionDataService)
        .findMostRecent(CREDENTIAL_NAME);
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "\"type\":\"" + parametizer.credentialType + "\","
            + "\"name\":\"" + CREDENTIAL_NAME + "\","
            + "\"value\":" + parametizer.credentialValue
            + "}");

    mockMvc.perform(request);

    verify(credentialVersionDataService, times(0)).save(any(CredentialVersion.class));
  }

  @Test
  public void updatingACredential_withOverwriteSetToFalse_persistsAnAuditEntry() throws Exception {
    CredentialVersion expectedCredentialVersion = parametizer.createCredential(encryptor);
    doReturn(expectedCredentialVersion)
        .when(credentialVersionDataService)
        .findMostRecent(CREDENTIAL_NAME);
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "\"type\":\"" + parametizer.credentialType + "\","
            + "\"name\":\"" + CREDENTIAL_NAME + "\","
            + "\"value\":" + parametizer.credentialValue
            + "}");

    mockMvc.perform(request);

    auditingHelper.verifyAuditing(CREDENTIAL_ACCESS, CREDENTIAL_NAME, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/data", 200);
  }

  private static abstract class TestParametizer {
    public final String credentialType;
    public final String credentialValue;

    public TestParametizer(String credentialType, String credentialValue) {
      this.credentialType = credentialType;
      this.credentialValue = credentialValue;
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
