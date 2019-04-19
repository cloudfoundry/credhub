package org.cloudfoundry.credhub.integration.v1.credentials;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.UUID;
import java.util.function.Consumer;

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

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import net.minidev.json.JSONObject;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.TestHelper;
import org.cloudfoundry.credhub.certificates.DefaultSetHandler;
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
import org.cloudfoundry.credhub.requests.BaseCredentialSetRequest;
import org.cloudfoundry.credhub.services.CredentialVersionDataService;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.utils.MultiJsonPathMatcher;
import org.cloudfoundry.credhub.utils.TestConstants;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.ArgumentCaptor;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Parameterized.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
public class CredentialsTypeSpecificSetIntegrationTest {
  @ClassRule
  public static final SpringClassRule SPRING_CLASS_RULE = new SpringClassRule();
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
  private static final JsonNode jsonNode;

  static {
    JsonNode tmp = null;
    try {
      tmp = new ObjectMapper().readTree(JSON_VALUE_JSON_STRING);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }
    jsonNode = tmp;
  }

  @Rule
  public final SpringMethodRule springMethodRule = new SpringMethodRule();
  @Parameterized.Parameter
  public TestParametizer parametizer;
  @Autowired
  private WebApplicationContext webApplicationContext;
  @SpyBean
  private CredentialVersionDataService credentialVersionDataService;
  @SpyBean
  private DefaultSetHandler setHandler;
  @MockBean
  private CurrentTimeProvider mockCurrentTimeProvider;
  @SpyBean
  private ObjectMapper objectMapper;
  @Autowired
  private Encryptor encryptor;
  private MockMvc mockMvc;

  @Parameterized.Parameters(name = "{0}")
  public static Collection<Object> parameters() {
    final UUID credentialUuid = UUID.randomUUID();

    final Collection<Object> params = new ArrayList<>();

    final TestParametizer valueParameters = new TestParametizer("value", "\"" + VALUE_VALUE + "\"") {
      @Override
      ResultMatcher jsonAssertions() {
        return MultiJsonPathMatcher.multiJsonPath("$.value", VALUE_VALUE);
      }

      @Override
      void credentialAssertions(final CredentialVersion credential) {
        assertThat(credential.getValue(), equalTo(VALUE_VALUE));
      }

      @Override
      CredentialVersion createCredential(final Encryptor encryptor) {
        ValueCredentialVersion valueCredentialVersion = new ValueCredentialVersion(CREDENTIAL_NAME);
        valueCredentialVersion.setEncryptor(encryptor);
        valueCredentialVersion.setValue(VALUE_VALUE);
        valueCredentialVersion.setUuid(credentialUuid);
        valueCredentialVersion.setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));

        return valueCredentialVersion;
      }
    };
    final TestParametizer passwordParameters = new TestParametizer("password", "\"" + PASSWORD_VALUE + "\"") {
      @Override
      ResultMatcher jsonAssertions() {
        return MultiJsonPathMatcher.multiJsonPath("$.value", PASSWORD_VALUE);
      }

      @Override
      void credentialAssertions(final CredentialVersion credential) {
        assertThat(((PasswordCredentialVersion) credential).getPassword(), equalTo(PASSWORD_VALUE));
      }

      @Override
      CredentialVersion createCredential(final Encryptor encryptor) {
        PasswordCredentialVersion passwordCredentialVersion = new PasswordCredentialVersion(CREDENTIAL_NAME);
        passwordCredentialVersion.setEncryptor(encryptor);
        passwordCredentialVersion.setPasswordAndGenerationParameters(PASSWORD_VALUE, null);
        passwordCredentialVersion.setUuid(credentialUuid);
        passwordCredentialVersion.setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));

        return passwordCredentialVersion;
      }
    };
    final TestParametizer certificateParameters = new TestParametizer("certificate", CERTIFICATE_VALUE_JSON_STRING) {
      @Override
      ResultMatcher jsonAssertions() {
        return MultiJsonPathMatcher.multiJsonPath(
          "$.value.certificate", TestConstants.TEST_CERTIFICATE,
          "$.value.private_key", TestConstants.TEST_PRIVATE_KEY,
          "$.value.ca", TestConstants.TEST_CA
        );
      }

      @Override
      void credentialAssertions(final CredentialVersion credential) {
        final CertificateCredentialVersion certificateCredential = (CertificateCredentialVersion) credential;
        assertThat(certificateCredential.getCa(), equalTo(TestConstants.TEST_CA));
        assertThat(certificateCredential.getCertificate(), equalTo(TestConstants.TEST_CERTIFICATE));
        assertThat(certificateCredential.getPrivateKey(), equalTo(TestConstants.TEST_PRIVATE_KEY));
      }

      @Override
      CredentialVersion createCredential(final Encryptor encryptor) {
        CertificateCredentialVersion certificateCredentialVersion = new CertificateCredentialVersion(CREDENTIAL_NAME);
        certificateCredentialVersion.setEncryptor(encryptor);
        certificateCredentialVersion.setCa(TestConstants.TEST_CA);
        certificateCredentialVersion.setCertificate(TestConstants.TEST_CERTIFICATE);
        certificateCredentialVersion.setPrivateKey(TestConstants.TEST_PRIVATE_KEY);
        certificateCredentialVersion.setUuid(credentialUuid);
        certificateCredentialVersion.setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));

        return certificateCredentialVersion;
      }
    };
    final TestParametizer sshParameters = new TestParametizer("ssh", SSH_VALUE_JSON_STRING) {
      @Override
      ResultMatcher jsonAssertions() {
        return MultiJsonPathMatcher.multiJsonPath(
          "$.value.public_key", TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT,
          "$.value.private_key", TestConstants.PRIVATE_KEY_4096,
          "$.value.public_key_fingerprint", "UmqxK9UJJR4Jrcw0DcwqJlCgkeQoKp8a+HY+0p0nOgc"
        );
      }

      @Override
      void credentialAssertions(final CredentialVersion credential) {
        final SshCredentialVersion sshCredential = (SshCredentialVersion) credential;
        assertThat(sshCredential.getPublicKey(), equalTo(TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT));
        assertThat(sshCredential.getPrivateKey(), equalTo(TestConstants.PRIVATE_KEY_4096));
      }

      @Override
      CredentialVersion createCredential(final Encryptor encryptor) {
        SshCredentialVersion sshCredentialVersion = new SshCredentialVersion(CREDENTIAL_NAME);
        sshCredentialVersion.setEncryptor(encryptor);
        sshCredentialVersion.setPrivateKey(TestConstants.PRIVATE_KEY_4096);
        sshCredentialVersion.setPublicKey(TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT);
        sshCredentialVersion.setUuid(credentialUuid);
        sshCredentialVersion.setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));

          return sshCredentialVersion;
      }
    };
    final TestParametizer rsaParameters = new TestParametizer("rsa", RSA_VALUE_JSON_STRING) {
      @Override
      ResultMatcher jsonAssertions() {
        return MultiJsonPathMatcher.multiJsonPath(
          "$.value.public_key", TestConstants.RSA_PUBLIC_KEY_4096,
          "$.value.private_key", TestConstants.PRIVATE_KEY_4096
        );
      }

      @Override
      void credentialAssertions(final CredentialVersion credential) {
        final RsaCredentialVersion rsaCredential = (RsaCredentialVersion) credential;
        assertThat(rsaCredential.getPublicKey(), equalTo(TestConstants.RSA_PUBLIC_KEY_4096));
        assertThat(rsaCredential.getPrivateKey(), equalTo(TestConstants.PRIVATE_KEY_4096));
      }

      @Override
      CredentialVersion createCredential(final Encryptor encryptor) {
        RsaCredentialVersion rsaCredentialVersion = new RsaCredentialVersion(CREDENTIAL_NAME);
        rsaCredentialVersion.setEncryptor(encryptor);
        rsaCredentialVersion.setPrivateKey(TestConstants.PRIVATE_KEY_4096);
        rsaCredentialVersion.setPublicKey(TestConstants.RSA_PUBLIC_KEY_4096);
        rsaCredentialVersion.setUuid(credentialUuid);
        rsaCredentialVersion.setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));

        return rsaCredentialVersion;
      }
    };
    final TestParametizer jsonParameters = new TestParametizer("json", JSON_VALUE_JSON_STRING) {
      @Override
      ResultMatcher jsonAssertions() {
        return MultiJsonPathMatcher.multiJsonPath("$.value", jsonValueMap);
      }

      @Override
      void credentialAssertions(final CredentialVersion credential) {
        final JsonCredentialVersion jsonCredential = (JsonCredentialVersion) credential;
        assertThat(jsonCredential.getValue(), equalTo(jsonNode));
      }

      @Override
      CredentialVersion createCredential(final Encryptor encryptor) {
        JsonCredentialVersion jsonCredentialVersion = new JsonCredentialVersion(CREDENTIAL_NAME);
        jsonCredentialVersion.setEncryptor(encryptor);
        jsonCredentialVersion.setValue(jsonNode);
        jsonCredentialVersion.setUuid(credentialUuid);
        jsonCredentialVersion.setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));

        return jsonCredentialVersion;
      }
    };
    final TestParametizer userParameters = new TestParametizer("user", USER_VALUE_JSON_STRING) {
      @Override
      ResultMatcher jsonAssertions() {
        return MultiJsonPathMatcher.multiJsonPath(
          "$.value.username", USERNAME_VALUE,
          "$.value.password", PASSWORD_VALUE
        );
      }

      @Override
      void credentialAssertions(final CredentialVersion credential) {
        final UserCredentialVersion userCredential = (UserCredentialVersion) credential;
        assertThat(userCredential.getUsername(), equalTo(USERNAME_VALUE));
        assertThat(userCredential.getPassword(), equalTo(PASSWORD_VALUE));
      }

      @Override
      CredentialVersion createCredential(final Encryptor encryptor) {
        UserCredentialVersion userCredentialVersion = new UserCredentialVersion(CREDENTIAL_NAME);
        userCredentialVersion.setEncryptor(encryptor);
        userCredentialVersion.setUsername(USERNAME_VALUE);
        userCredentialVersion.setPassword(PASSWORD_VALUE);
        userCredentialVersion.setUuid(credentialUuid);
        userCredentialVersion.setVersionCreatedAt(FROZEN_TIME.minusSeconds(1));

        return userCredentialVersion;
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
  public void setUp() {
    final Consumer<Long> fakeTimeSetter = TestHelper.mockOutCurrentTimeProvider(mockCurrentTimeProvider);

    fakeTimeSetter.accept(FROZEN_TIME.toEpochMilli());
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();
  }

  @Test
  public void settingACredential_shouldAcceptAnyCasingForType() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
        "\"type\":\"" + parametizer.credentialType.toUpperCase() + "\"," +
        "\"value\":" + parametizer.credentialValue +
        "}");

    final ResultActions response = mockMvc.perform(request);

    final ArgumentCaptor<CredentialVersion> argumentCaptor = ArgumentCaptor.forClass(CredentialVersion.class);
    verify(credentialVersionDataService, times(1)).save(argumentCaptor.capture());

    final UUID uuid = argumentCaptor.getValue().getUuid();
    assertNotNull(uuid);

    response
      .andExpect(status().isOk())
      .andExpect(parametizer.jsonAssertions())
      .andExpect(MultiJsonPathMatcher.multiJsonPath(
        "$.type", parametizer.credentialType,
        "$.id", uuid.toString(),
        "$.version_created_at", FROZEN_TIME.toString()))
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON));
  }

  @Test
  public void settingACredential_returnsTheExpectedResponse() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
        "\"type\":\"" + parametizer.credentialType + "\"," +
        "\"value\":" + parametizer.credentialValue +
        "}");

    final ResultActions response = mockMvc.perform(request);

    final ArgumentCaptor<CredentialVersion> argumentCaptor = ArgumentCaptor.forClass(CredentialVersion.class);
    verify(credentialVersionDataService, times(1)).save(argumentCaptor.capture());

    final UUID uuid = argumentCaptor.getValue().getUuid();
    assertNotNull(uuid);

    response.andExpect(parametizer.jsonAssertions())
      .andExpect(MultiJsonPathMatcher.multiJsonPath(
        "$.type", parametizer.credentialType,
        "$.id", uuid.toString(),
        "$.version_created_at", FROZEN_TIME.toString()))
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON));
  }

  @Test
  public void settingACredential_expectsDataServiceToPersistTheCredential() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
        "\"type\":\"" + parametizer.credentialType + "\"," +
        "\"value\":" + parametizer.credentialValue +
        "}");
    final ArgumentCaptor<CredentialVersion> argumentCaptor = ArgumentCaptor.forClass(CredentialVersion.class);

    mockMvc.perform(request);

    verify(setHandler, times(1))
      .handle(isA(BaseCredentialSetRequest.class));
    verify(credentialVersionDataService, times(1)).save(argumentCaptor.capture());

    final CredentialVersion newCredentialVersion = argumentCaptor.getValue();

    parametizer.credentialAssertions(newCredentialVersion);
  }

  @Test
  public void validationExceptionsAreReturnedAsErrorMessages() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "\"name\":\"" + CREDENTIAL_NAME + "\"," +
        "\"type\":\"" + parametizer.credentialType + "\"," +
        "\"value\":" + parametizer.credentialValue +
        "}");

    final BaseCredentialSetRequest requestObject = mock(BaseCredentialSetRequest.class);
    doThrow(new ParameterizedValidationException(ErrorMessages.BAD_REQUEST)).when(requestObject).validate();
    doReturn(requestObject).when(objectMapper).readValue(any(InputStream.class), any(JavaType.class));

    mockMvc.perform(request)
      .andExpect(status().isBadRequest())
      .andExpect(content().json("{\"error\":\"The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.\"}"));
  }

  @Test
  public void updatingACredential_returnsTheExistingCredentialVersion() throws Exception {
    doReturn(parametizer.createCredential(encryptor)).when(credentialVersionDataService).findMostRecent(CREDENTIAL_NAME);

    final MockHttpServletRequestBuilder put = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"type\":\"" + parametizer.credentialType + "\"," +
        "  \"name\":\"" + CREDENTIAL_NAME + "\"," +
        "  \"value\":" + parametizer.credentialValue +
        "}");

    final ResultActions response = mockMvc.perform(put);

    final ArgumentCaptor<CredentialVersion> argumentCaptor = ArgumentCaptor.forClass(CredentialVersion.class);
    verify(credentialVersionDataService, times(1)).save(argumentCaptor.capture());

    final UUID uuid = argumentCaptor.getValue().getUuid();
    assertNotNull(uuid);

    response.andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(parametizer.jsonAssertions())
      .andExpect(MultiJsonPathMatcher.multiJsonPath(
        "$.type", parametizer.credentialType,
        "$.id", uuid.toString(),
        "$.version_created_at", FROZEN_TIME.toString()));
  }

  @Test
  public void updatingACredential_persistsTheCredential() throws Exception {
    doReturn(parametizer.createCredential(encryptor)).when(credentialVersionDataService).findMostRecent(CREDENTIAL_NAME);

    final MockHttpServletRequestBuilder put = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"type\":\"" + parametizer.credentialType + "\"," +
        "  \"name\":\"" + CREDENTIAL_NAME + "\"," +
        "  \"value\":" + parametizer.credentialValue + "" +
        "}");

    mockMvc.perform(put);

    final CredentialVersion credentialVersion = credentialVersionDataService.findMostRecent(CREDENTIAL_NAME);
    parametizer.credentialAssertions(credentialVersion);
  }


  private static abstract class TestParametizer {
    final String credentialType;
    final String credentialValue;

    TestParametizer(final String credentialType, final String credentialValue) {
      super();
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
