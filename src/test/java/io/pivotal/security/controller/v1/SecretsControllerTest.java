package io.pivotal.security.controller.v1;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.fake.FakeUuidGenerator;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.mapper.StringGeneratorRequestTranslator;
import io.pivotal.security.repository.CertificateAuthorityRepository;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.view.CertificateSecret;
import io.pivotal.security.view.StringSecret;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.context.MessageSource;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.util.JsonExpectationsHelper;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.ConfigurableWebApplicationContext;

import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.Locale;
import java.util.function.Consumer;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.*;
import static junit.framework.TestCase.assertNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
@ActiveProfiles({"unit-test", "FakeUuidGenerator"})
public class SecretsControllerTest {

  private static final JsonExpectationsHelper jsonExpectationsHelper = new JsonExpectationsHelper();

  @Autowired
  private MessageSource messageSource;

  @Autowired
  protected ConfigurableWebApplicationContext context;

  @Autowired
  private ObjectMapper serializingObjectMapper;

  @Autowired
  private SecretRepository secretRepository;

  @Autowired
  private CertificateAuthorityRepository caAuthorityRepository;

  @InjectMocks
  @Autowired
  private SecretsController secretsController;

  @Autowired
  ConfigurableEnvironment environment;

  @Autowired
  FakeUuidGenerator fakeUuidGenerator;

  @Mock
  StringGeneratorRequestTranslator stringGeneratorRequestTranslator;

  @Mock
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  @Mock
  private ResourceServerTokenServices tokenServices;

  private MockMvc mockMvc;
  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);
  private SecurityContext oldContext;
  private Consumer<Long> fakeTimeSetter;
  private NamedStringSecret expectedSecret;

  private String urlPath;
  private String secretName;

  {
    wireAndUnwire(this);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
      secretName = uniquify("secret-identifier");
      urlPath = "/api/v1/data/" + secretName;

      oldContext = SecurityContextHolder.getContext();
      Authentication authentication = mock(Authentication.class);
      OAuth2AuthenticationDetails authenticationDetails = mock(OAuth2AuthenticationDetails.class);
      when(authenticationDetails.getTokenValue()).thenReturn("abcde");
      when(authentication.getDetails()).thenReturn(authenticationDetails);
      OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
      ImmutableMap<String, Object> additionalInfo = ImmutableMap.of(
          "iat", 1406568935,
          "user_name", "marissa",
          "user_id", "12345-6789a",
          "iss", 3333333333L);
      when(accessToken.getAdditionalInformation()).thenReturn(additionalInfo);
      when(accessToken.getExpiration()).thenReturn(new Date(3333333333000L));
      when(tokenServices.readAccessToken("abcde")).thenReturn(accessToken);

      SecurityContext securityContext = mock(SecurityContext.class);
      when(securityContext.getAuthentication()).thenReturn(authentication);
      SecurityContextHolder.setContext(securityContext);
    });

    afterEach(() -> {
      SecurityContextHolder.setContext(oldContext);
    });

    describe("string secrets", () -> {
      beforeEach(() -> {
        expectedSecret = new NamedStringSecret(secretName)
            .setValue("very-secret")
            .setUpdatedAt(frozenTime);
        when(stringGeneratorRequestTranslator.makeEntity(any(String.class))).thenReturn(expectedSecret);
      });

      it("can save a client-provided string secret", () -> {
        String requestJson = "{\"type\":\"value\",\"value\":\"very-secret\"}";
        String resultJson = makeValueResultJsonString("very-secret");

        expectSuccess(putRequestBuilder(urlPath, requestJson), resultJson);

        NamedStringSecret stored = (NamedStringSecret) secretRepository.findOneByName(secretName);
        jsonExpectationsHelper.assertJsonEqual(resultJson, json(new StringSecret().generateView(stored)), true);
      });

      it("can update a client-provided string secret", () -> {
        String requestJson = "{\"type\":\"value\",\"value\":\"very-secret\"}";
        String resultJson = makeValueResultJsonString("very-secret");
        expectSuccess(putRequestBuilder(urlPath, requestJson), resultJson);

        String requestJson2 = "{\"type\":\"value\",\"value\":\"very-secret-2\"}";
        String resultJson2 = makeValueResultJsonString("very-secret-2");
        expectSuccess(putRequestBuilder(urlPath, requestJson2), resultJson2);

        StringSecret expected = new StringSecret("very-secret-2");
        expected.setUpdatedAt(frozenTime);
        NamedStringSecret stored = (NamedStringSecret) secretRepository.findOneByName(secretName);
        jsonExpectationsHelper.assertJsonEqual(resultJson2, json(new StringSecret().generateView(stored)), true);
      });

      it("can fetch a string secret by name", () -> {
        NamedStringSecret stringSecret = new NamedStringSecret(secretName, "value").setValue("stringSecret contents");
        secretRepository.save(stringSecret);
        String expectedJson = json(new StringSecret().generateView(stringSecret));

        expectSuccess(get(urlPath), expectedJson);
      });

      it("can fetch a string secret by uuid", () -> {
        NamedStringSecret stringSecret = new NamedStringSecret(secretName, "value").setValue("stringSecret contents");
        secretRepository.save(stringSecret);
        String expectedJson = json(new StringSecret().generateView(stringSecret));

        expectSuccess(get("/api/v1/data?id=" + fakeUuidGenerator.getLastUuid()), expectedJson);
      });

      it("can generate string secret", () -> {
        StringSecret expectedStringSecret = new StringSecret("very-secret")
            .setUpdatedAt(frozenTime)
            .setUuid(fakeUuidGenerator.peekNextUuid())
            .setType("value");

        String expectedJson = json(expectedStringSecret);
        expectSuccess(postRequestBuilder(urlPath, "{\"type\":\"value\"}"), expectedJson);
        assertThat((NamedStringSecret) secretRepository.findOneByName(secretName), BeanMatchers.theSameAs(expectedSecret).excludeProperty("Id"));
      });

      it("can generate string secret with empty parameters map", () -> {
        StringSecret expectedStringSecret = new StringSecret("very-secret")
            .setUpdatedAt(frozenTime)
            .setUuid(fakeUuidGenerator.peekNextUuid())
            .setType("value");

        String expectedJson = json(expectedStringSecret);
        expectSuccess(postRequestBuilder(urlPath, "{\"type\":\"value\"," + getUpdatedAtJson() + ",\"parameters\":{}}"), expectedJson);
        NamedStringSecret stored = (NamedStringSecret) secretRepository.findOneByName(secretName);
        assertThat(new StringSecret().generateView(stored), BeanMatchers.theSameAs(expectedStringSecret));
      });

      it("uses parameters to generate string secret", () -> {
        StringSecret expectedStringSecret = new StringSecret("very-secret")
            .setUpdatedAt(frozenTime)
            .setUuid(fakeUuidGenerator.peekNextUuid())
            .setType("value");
        String expectedJson = json(expectedStringSecret);
        String requestJson = "{" +
            "\"type\":\"value\"," +
            "\"parameters\":{" +
            "\"length\":42, " +
            "\"exclude_special\": true," +
            "\"exclude_number\": true," +
            "\"exclude_upper\": true" +
            "}" +
            "}";
        expectSuccess(postRequestBuilder(urlPath, requestJson), expectedJson);
        NamedStringSecret stored = (NamedStringSecret) secretRepository.findOneByName(secretName);
        assertThat(new StringSecret().generateView(stored), BeanMatchers.theSameAs(expectedStringSecret));
      });
    });

//    todo reuse suite from secrets; Dan has new story for removing
    describe("password secrets", () -> {
      beforeEach(() -> {
        expectedSecret = new NamedStringSecret(secretName)
            .setValue("my-password")
            .setUpdatedAt(frozenTime);
        when(stringGeneratorRequestTranslator.makeEntity(any(String.class))).thenReturn(expectedSecret);
      });

      it("can save a client-provided password secret", () -> {
        String requestJson = "{\"type\":\"password\",\"value\":\"my-password\"}";
        String resultJson = makePasswordResultJsonString("my-password");

        expectSuccess(putRequestBuilder(urlPath, requestJson), resultJson);

        NamedStringSecret stored = (NamedStringSecret) secretRepository.findOneByName(secretName);
        jsonExpectationsHelper.assertJsonEqual(resultJson, json(new StringSecret().generateView(stored)), true);
      });

      it("can update a client-provided password secret", () -> {
        String requestJson = "{\"type\":\"password\",\"value\":\"my-password\"}";
        String resultJson = makePasswordResultJsonString("my-password");
        expectSuccess(putRequestBuilder(urlPath, requestJson), resultJson);

        String requestJson2 = "{\"type\":\"password\",\"value\":\"my-password-2\"}";
        String resultJson2 = makePasswordResultJsonString("my-password-2");
        expectSuccess(putRequestBuilder(urlPath, requestJson2), resultJson2);

        StringSecret expected = new StringSecret("my-password-2");
        expected.setUpdatedAt(frozenTime);
        NamedStringSecret stored = (NamedStringSecret) secretRepository.findOneByName(secretName);
        jsonExpectationsHelper.assertJsonEqual(resultJson2, json(new StringSecret().generateView(stored)), true);
      });

      it("can fetch a password secret by name", () -> {
        NamedStringSecret stringSecret = new NamedStringSecret(secretName).setValue("stringSecret contents");
        secretRepository.save(stringSecret);
        String expectedJson = json(new StringSecret().generateView(stringSecret));

        expectSuccess(get(urlPath), expectedJson);
      });

      it("can generate password secret", () -> {
        StringSecret expectedStringSecret = new StringSecret("my-password")
            .setUpdatedAt(frozenTime)
            .setUuid(fakeUuidGenerator.peekNextUuid())
            .setType("password");

        String expectedJson = json(expectedStringSecret);
        expectSuccess(postRequestBuilder(urlPath, "{\"type\":\"password\"}"), expectedJson);
        assertThat((NamedStringSecret) secretRepository.findOneByName(secretName), BeanMatchers.theSameAs(expectedSecret).excludeProperty("Id"));
      });

      it("can generate password secret with empty parameters map", () -> {
        StringSecret expectedStringSecret = new StringSecret("my-password")
            .setUpdatedAt(frozenTime)
            .setUuid(fakeUuidGenerator.peekNextUuid())
            .setType("password");

        String expectedJson = json(expectedStringSecret);
        expectSuccess(postRequestBuilder(urlPath, "{\"type\":\"password\"," + getUpdatedAtJson() + ",\"parameters\":{}}"), expectedJson);
        NamedStringSecret stored = (NamedStringSecret) secretRepository.findOneByName(secretName);
        assertThat(new StringSecret().generateView(stored), BeanMatchers.theSameAs(expectedStringSecret));
      });

      it("uses parameters to generate password secret", () -> {
        StringSecret expectedStringSecret = new StringSecret("my-password")
            .setUpdatedAt(frozenTime)
            .setUuid(fakeUuidGenerator.peekNextUuid())
            .setType("password");

        String expectedJson = json(expectedStringSecret);
        String requestJson = "{" +
            "\"type\":\"password\"," +
            "\"parameters\":{" +
            "\"length\":42, " +
            "\"exclude_special\": true," +
            "\"exclude_number\": true," +
            "\"exclude_upper\": true" +
            "}" +
            "}";
        expectSuccess(postRequestBuilder(urlPath, requestJson), expectedJson);
        NamedStringSecret stored = (NamedStringSecret) secretRepository.findOneByName(secretName);
        assertThat(new StringSecret().generateView(stored), BeanMatchers.theSameAs(expectedStringSecret));
      });
    });

    describe("certificate secrets", () -> {
      it("can fetch a certificate secret", () -> {
        NamedCertificateSecret certificateSecret = new NamedCertificateSecret(secretName)
            .setRoot("get-ca")
            .setCertificate("get-certificate")
            .setPrivateKey("get-priv");
        secretRepository.save(certificateSecret);

        String expectedJson = json(new CertificateSecret().generateView(certificateSecret));

        expectSuccess(get(urlPath), expectedJson);
      });

      it("can store a client-provided certificate", () -> {
        String requestJson = "{\"type\":\"certificate\",\"value\":{\"root\":\"my-ca\",\"certificate\":\"my-certificate\",\"private_key\":\"my-priv\"}}";
        String resultJson = makeCertificateResultJsonString("my-ca");

        expectSuccess(putRequestBuilder(urlPath, requestJson), resultJson);

        NamedCertificateSecret expectedCertificateSecret = new NamedCertificateSecret(secretName)
            .setRoot("my-ca")
            .setCertificate("my-certificate")
            .setPrivateKey("my-priv")
            .setUuid(fakeUuidGenerator.getLastUuid())
            .setUpdatedAt(frozenTime);
        final NamedCertificateSecret storedSecret = (NamedCertificateSecret) secretRepository.findOneByName(secretName);
        assertThat(storedSecret, BeanMatchers.theSameAs(expectedCertificateSecret).excludeProperty("Id").excludeProperty("Nonce").excludeProperty("EncryptedValue"));
        assertNull(caAuthorityRepository.findOneByName(secretName));
      });

      it("returns JSON that contains nulls in fields the client did not provide", () -> {
        String requestJson = "{\"type\":\"certificate\",\"value\":{\"root\":null,\"certificate\":\"my-certificate\",\"private_key\":\"my-priv\"}}";
        String resultJson = makeCertificateResultJsonString(null);

        expectSuccess(putRequestBuilder(urlPath, requestJson), resultJson);
      });

      it("can generate certificates", () -> {
        NamedCertificateSecret expectedSecret = new NamedCertificateSecret(secretName)
            .setRoot("my-ca")
            .setCertificate("my-certificate")
            .setPrivateKey("my-priv")
            .setUpdatedAt(frozenTime);
        when(certificateGeneratorRequestTranslator.makeEntity(any(String.class))).thenReturn(expectedSecret);

        String requestJson = "{" +
            "\"type\":\"certificate\"," +
            "\"parameters\":{" +
            "\"common_name\":\"My Common Name\", " +
            "\"organization\": \"organization.io\"," +
            "\"organization_unit\": \"My Unit\"," +
            "\"locality\": \"My Locality\"," +
            "\"state\": \"My State\"," +
            "\"country\": \"My Country\"," +
            "\"alternative_names\": [\"My Alternative Name 1\", \"My Alternative Name 2\"]" +
            "}" +
            "}";
        CertificateSecret certificateSecret = new CertificateSecret("my-ca", "my-certificate", "my-priv")
            .setUpdatedAt(frozenTime)
            .setUuid(fakeUuidGenerator.peekNextUuid());
        String expectedJson = json(certificateSecret);
        expectSuccess(postRequestBuilder(urlPath, requestJson), expectedJson);
        assertThat((NamedCertificateSecret) secretRepository.findOneByName(secretName), BeanMatchers.theSameAs(expectedSecret).excludeProperty("Id"));
      });

      it("can store nulls in client-supplied certificate secret", () -> {
        permuteTwoEmptiesTest(null);
      });

      it("can store empty strings in client-supplied certificate secret", () -> {
        permuteTwoEmptiesTest("");
      });

      it("returns bad request (400) if all certificate fields are empty", () -> {

        new PutCertificateSimulator("", "", "")
            .setExpectation(400, "error.missing_certificate_credentials")
            .execute();
      });
    });

    it("can delete a secret", () -> {
      NamedStringSecret stringSecret = new NamedStringSecret(secretName).setValue("super stringSecret do not tell");

      secretRepository.save(stringSecret);
      mockMvc.perform(delete(urlPath))
          .andExpect(status().isOk());
    });

    describe("returns not found (404) when getting missing secrets", () -> {
      it("fails as expected", () -> {
        expectErrorKey(get(urlPath), HttpStatus.NOT_FOUND, "error.secret_not_found");
      });
    });

    describe("returns not found (404) when deleting missing secrets", () -> {
      it("fails as expected", () -> {
        expectErrorKey(delete(urlPath), HttpStatus.NOT_FOUND, "error.secret_not_found");
      });
    });

    it("returns bad request (400) for PUT with empty JSON", () -> {
      expectErrorKey(putRequestBuilder(urlPath, "{}"), HttpStatus.BAD_REQUEST, "error.type_invalid");
    });

    it("returns bad request (400) for PUT with empty body", () -> {
      expectErrorKey(putRequestBuilder(urlPath, ""), HttpStatus.BAD_REQUEST, "error.type_invalid");
    });

    it("returns bad request (400) for PUT with missing type", () -> {
      expectErrorKey(putRequestBuilder(urlPath, "{\"value\":\"my-secret\"}"), HttpStatus.BAD_REQUEST, "error.type_invalid");
    });

    it("returns bad request (400) for PUT with invalid JSON", () -> {
      expectErrorMessage(putRequestBuilder(urlPath, "{asdfasdfas}"), HttpStatus.BAD_REQUEST,
          "The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.");
    });

    it("returns bad request (400) for PUT when client does not specify a value", () -> {
      expectErrorKey(putRequestBuilder(urlPath, "{\"type\":\"value\"}"), HttpStatus.BAD_REQUEST, "error.missing_string_secret_value");
    });

    it("returns bad request (400) for PUT without a type parameter", () -> {
      expectErrorKey(putRequestBuilder(urlPath, "{\"value\":\"my-secret\"}"), HttpStatus.BAD_REQUEST, "error.type_invalid");
    });

    it("returns bad request (400) for PUT with unsupported type", () -> {
      expectErrorKey(putRequestBuilder(urlPath, "{\"type\":\"foo\", \"value\":\"my-secret\"}"), HttpStatus.BAD_REQUEST, "error.type_invalid");
    });

    it("returns bad request (400) if client tries to change the type of a secret", () -> {
      NamedStringSecret stringSecret = new NamedStringSecret(secretName).setValue("password");
      secretRepository.save(stringSecret);

      String requestJson = "{\"type\":\"certificate\",\"value\":{\"root\":null,\"certificate\":\"my-certificate\",\"private_key\":\"my-priv\"}}";
      expectErrorKey(putRequestBuilder(urlPath, requestJson), HttpStatus.BAD_REQUEST, "error.type_mismatch");
    });

    it("returns bad request (400) if request body is empty", () -> {
      expectErrorKey(postRequestBuilder(urlPath, ""), HttpStatus.BAD_REQUEST, "error.type_invalid");
    });

    it("returns bad request (400) if JSON is empty", () -> {
      expectErrorKey(postRequestBuilder(urlPath, "{}"), HttpStatus.BAD_REQUEST, "error.type_invalid");
    });

    it("content negotiation and path matching are disabled", () -> {
      String testSecretName = uniquify("test");
      doPutValue(testSecretName, "abc");
      doPutValue(uniquify("test.foo"), "def");

      mockMvc.perform(get("/api/v1/data/" + testSecretName))
          .andExpect(status().isOk())
          .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(jsonPath("$.value").value("abc"));
    });
  }

  private String makeValueResultJsonString(final String value) {
    return "{\"id\":\"" + fakeUuidGenerator.peekNextUuid() + "\",\"type\":\"value\"," + getUpdatedAtJson() + ",\"value\":\"" + value + "\"}";
  }

  private String makePasswordResultJsonString(final String value) {
    return "{\"id\":\"" + fakeUuidGenerator.peekNextUuid() + "\",\"type\":\"password\"," + getUpdatedAtJson() + ",\"value\":\"" + value + "\"}";
  }

  private String makeCertificateResultJsonString(String root) {
    String encodedJson = root != null ? "\"" + root + "\"" : "null";
    return "{\"id\":\"" + fakeUuidGenerator.peekNextUuid() + "\",\"type\":\"certificate\"," + getUpdatedAtJson() + ",\"value\":{\"root\":" + encodedJson + ",\"certificate\":\"my-certificate\",\"private_key\":\"my-priv\"}}";
  }

  private void expectSuccess(RequestBuilder requestBuilder, String returnedJson) throws Exception {
    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(returnedJson, true));
  }

  private void expectErrorKey(RequestBuilder requestBuilder, HttpStatus httpStatus, String errorKey) throws Exception {
    final String errorMessage = messageSource.getMessage(errorKey, new Object[0], Locale.getDefault());
    expectErrorMessage(requestBuilder, httpStatus, errorMessage);
  }

  private void expectErrorMessage(RequestBuilder requestBuilder, HttpStatus httpStatus, String errorMessage) throws Exception {
    mockMvc.perform(requestBuilder)
        .andExpect(status().is(httpStatus.value()))
        .andExpect(content().json("{\"error\": \"" + errorMessage + "\"}"));
  }

  private String getUpdatedAtJson() {
    return "\"updated_at\":\"2014-05-13T19:56:41Z\"";
  }

  private void permuteTwoEmptiesTest(String emptyValue) throws Exception {
    new PutCertificateSimulator(emptyValue, emptyValue, "my-priv")
        .setExpectation(200)
        .execute();

    new PutCertificateSimulator("my-ca", emptyValue, emptyValue)
        .setExpectation(200)
        .execute();

    new PutCertificateSimulator(emptyValue, "my-certificate", emptyValue)
        .setExpectation(200)
        .execute();
  }

  private void doPutValue(String secretName, String secretValue) throws Exception {
    String requestJson = "{\"type\":\"value\",\"value\":\"" + secretValue + "\"}";
    String resultJson = "{\"id\":\"" + fakeUuidGenerator.peekNextUuid() + "\",\"type\":\"value\"," + getUpdatedAtJson() + ",\"value\":\"" + secretValue + "\"}";

    expectSuccess(putRequestBuilder("/api/v1/data/" + secretName, requestJson), resultJson);
  }

  private RequestBuilder putRequestBuilder(String path, String requestBody) {
    return put(path)
        .content(requestBody)
        .contentType(MediaType.APPLICATION_JSON_UTF8);
  }

  private RequestBuilder postRequestBuilder(String path, String requestBody) {
    return post(path)
        .content(requestBody)
        .contentType(MediaType.APPLICATION_JSON_UTF8);
  }

  private String json(Object o) throws IOException {
    return serializingObjectMapper.writeValueAsString(o);
  }

  class PutCertificateSimulator {
    private final String ca;
    private final String certificate;
    private final String privateKey;
    private int statusCode;
    private String badResponseJson;

    PutCertificateSimulator(String ca, String certificate, String privateKey) {
      this.ca = ca;
      this.certificate = certificate;
      this.privateKey = privateKey;
    }

    void execute() throws Exception {
      String localSecretName = uniquify("whatever");
      CertificateSecret certificateSecretForRequest = new CertificateSecret(ca, certificate, privateKey);
      CertificateSecret certificateSecretForResponse = new CertificateSecret(
          transformEmptyToNull(ca),
          transformEmptyToNull(certificate),
          transformEmptyToNull(privateKey))
          .setUpdatedAt(frozenTime);

      String requestJson = json(certificateSecretForRequest);

      boolean isHttpOk = statusCode == 200;
      ResultMatcher expectedStatus = isHttpOk ? status().isOk() : status().isBadRequest();
      ResultActions result = mockMvc.perform(putRequestBuilder("/api/v1/data/" + localSecretName, requestJson))
          .andExpect(expectedStatus);
      NamedCertificateSecret certificateFromDb = (NamedCertificateSecret) secretRepository.findOneByName(localSecretName);

      if (isHttpOk) {
        assertThat(new CertificateSecret().generateView(certificateFromDb),
            BeanMatchers.theSameAs(certificateSecretForResponse)
                .excludeProperty("Uuid"));
      } else {
        assertNull(certificateFromDb);
        result.andExpect(content().json(badResponseJson));
      }
    }

    private String transformEmptyToNull(String param) {
      return "".equals(param) ? null : param;
    }

    PutCertificateSimulator setExpectation(int statusCode) {
      return setExpectation(statusCode, null);
    }

    PutCertificateSimulator setExpectation(int statusCode, String errorKey) {
      this.statusCode = statusCode;
      if (errorKey != null) {
        final String errorMessage = messageSource.getMessage(errorKey, new Object[0], Locale.getDefault());
        badResponseJson = "{\"error\": \"" + errorMessage + "\"}";
      }
      return this;
    }
  }
}
