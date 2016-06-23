package io.pivotal.security.controller.v1;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.MockitoSpringTest;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.repository.InMemorySecretRepository;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.view.CertificateSecret;
import io.pivotal.security.view.StringSecret;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.ConfigurableWebApplicationContext;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;

import static java.time.format.DateTimeFormatter.ofPattern;
import static junit.framework.TestCase.assertNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Transactional
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
public class SecretsControllerTest extends MockitoSpringTest {

  @Autowired
  protected ConfigurableWebApplicationContext context;

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private InMemorySecretRepository secretRepository;

  @InjectMocks
  @Autowired
  private SecretsController secretsController;

  @Autowired @Qualifier("currentTimeProvider")
  CurrentTimeProvider currentTimeProvider;

  @Mock
  private SecretGenerator<StringSecretParameters, StringSecret> stringSecretGenerator;

  @Mock
  private SecretGenerator<CertificateSecretParameters, CertificateSecret> certificateGenerator;

  private MockMvc mockMvc;

  private final ZoneId utc = ZoneId.of("UTC");
  private LocalDateTime frozenTime;

  @Before
  public void setUp() {
    freeze();
    mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
  }

  @After
  public void tearDown() {
    currentTimeProvider.reset();
  }

  @Test
  public void validPutSecret() throws Exception {
    String requestJson = "{" + getUpdatedAtJson() + ",\"type\":\"value\",\"value\":\"secret contents\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(requestJson));

    StringSecret expected = new StringSecret("secret contents");
    expected.setUpdatedAt(frozenTime);
    Assert.assertThat(secretRepository.findOneByName("secret-identifier").generateView(), BeanMatchers.theSameAs(expected));
  }

  private String getUpdatedAtJson() {
    return "\"updated_at\":\"" + frozenTime.format(ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")) + "\"";
  }

  @Test
  public void validGetStringSecret() throws Exception {
    NamedStringSecret stringSecret = new NamedStringSecret("whatever").setValue("stringSecret contents");

    secretRepository.save(stringSecret);

    String expectedJson = json(stringSecret.generateView());

    mockMvc.perform(get("/api/v1/data/whatever"))
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));
  }

  @Test
  public void validGetCertificateSecret() throws Exception {
    NamedCertificateSecret certificateSecret = new NamedCertificateSecret("whatever")
        .setCa("get-ca")
        .setPub("get-pub")
        .setPriv("get-priv");

    secretRepository.save(certificateSecret);

    String expectedJson = json(certificateSecret.generateView());

    mockMvc.perform(get("/api/v1/data/whatever"))
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));
  }

  @Test
  public void validPutCertificate() throws Exception {
    String requestJson = "{" + getUpdatedAtJson() + ",\"type\":\"certificate\",\"certificate\":{\"ca\":\"my-ca\",\"public\":\"my-pub\",\"private\":\"my-priv\"}}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(requestJson));

    CertificateSecret certificateSecret = new CertificateSecret("my-ca", "my-pub", "my-priv").setUpdatedAt(frozenTime);
    Assert.assertThat(secretRepository.findOneByName("secret-identifier").generateView(), BeanMatchers.theSameAs(certificateSecret));
  }

  @Test
  public void validPutCertificate_showsNullsInReturnedJson() throws Exception {
    String requestJson = "{\"type\":\"certificate\",\"certificate\":{\"ca\":null,\"public\":\"my-pub\",\"private\":\"my-priv\"}}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(requestJson));
  }

  @Test
  public void findOneByNameWithInvalidVersion() throws Exception {
    NamedStringSecret stringSecret = new NamedStringSecret("whatever").setValue("stringSecret contents");

    secretRepository.save(stringSecret);

    mockMvc.perform(get("/api/v2/data/whatever"))
        .andExpect(status().isNotFound());
  }

  @Test
  public void validDeleteSecret() throws Exception {
    NamedStringSecret stringSecret = new NamedStringSecret("whatever").setValue("super stringSecret do not tell");

    secretRepository.save(stringSecret);

    mockMvc.perform(delete("/api/v1/data/whatever"))
        .andExpect(status().isOk());

    Assert.assertNull(secretRepository.findOneByName("whatever"));
  }

  @Test
  public void generateSecretWithNoParameters() throws Exception {
    StringSecret expectedStringSecret = new StringSecret("very-secret").setUpdatedAt(frozenTime);
    when(stringSecretGenerator.generateSecret(any(StringSecretParameters.class))).thenReturn(expectedStringSecret);

    String expectedJson = json(expectedStringSecret);

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/my-secret", "{\"type\":\"value\"}");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));

    assertThat(secretRepository.findOneByName("my-secret").generateView(), BeanMatchers.theSameAs(expectedStringSecret));
  }

  @Test
  public void generateStringSecretWithEmptyParameters() throws Exception {
    StringSecret expectedStringSecret = new StringSecret("very-secret").setUpdatedAt(frozenTime);
    when(stringSecretGenerator.generateSecret(any(StringSecretParameters.class))).thenReturn(expectedStringSecret);

    String expectedJson = json(expectedStringSecret);

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/my-secret", "{" +  getUpdatedAtJson() + ",\"type\":\"value\",\"parameters\":{}}");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));

    assertThat(secretRepository.findOneByName("my-secret").generateView(), BeanMatchers.theSameAs(expectedStringSecret));
  }

  @Test
  public void generateStringSecretWithParameters() throws Exception {
    StringSecret expectedStringSecret = new StringSecret("long-secret").setUpdatedAt(frozenTime);
    when(stringSecretGenerator.generateSecret(any(StringSecretParameters.class))).thenReturn(expectedStringSecret);

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

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/my-secret", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));

    assertThat(secretRepository.findOneByName("my-secret").generateView(), BeanMatchers.theSameAs(expectedStringSecret));
  }

  @Test
  public void generateStringSecretWithDifferentParameters() throws Exception {
    StringSecret expectedStringSecret = new StringSecret("long-secret").setUpdatedAt(frozenTime);
    when(stringSecretGenerator.generateSecret(any(StringSecretParameters.class))).thenReturn(expectedStringSecret);

    String expectedJson = json(expectedStringSecret);

    String requestJson = "{" +
        "\"type\":\"value\"," +
        "\"parameters\":{" +
        "\"length\":42, " +
        "\"exclude_special\": true," +
        "\"exclude_lower\": true" +
        "}" +
        "}";

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/my-secret", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));

    assertThat(secretRepository.findOneByName("my-secret").generateView(), BeanMatchers.theSameAs(expectedStringSecret));
  }

  @Test
  public void generateStringSecretWithAllExcludeParameters() throws Exception {
    String badResponse = "{ \"error\": \"The combination of parameters in the request is not allowed. Please validate your input and retry your request.\" }";
    String requestJson = "{" +
        "\"type\":\"value\"," +
        "\"parameters\":{" +
        "\"exclude_special\": true," +
        "\"exclude_number\": true," +
        "\"exclude_upper\": true," +
        "\"exclude_lower\": true" +
        "}" +
        "}";

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/my-secret", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().json(badResponse));
  }


  @Test
  public void generateCertificateWithAllParametersSucceeds() throws Exception {
    CertificateSecret certificateSecret = new CertificateSecret("my-ca", "my-pub", "my-priv").setUpdatedAt(frozenTime);
    when(certificateGenerator.generateSecret(any(CertificateSecretParameters.class))).thenReturn(certificateSecret);

    String requestJson = "{" +
            "\"type\":\"certificate\"," +
            "\"parameters\":{" +
            "\"common_name\":\"My Common Name\", " +
            "\"organization\": \"organization.io\"," +
            "\"organization_unit\": \"My Unit\"," +
            "\"locality\": \"My Locality\"," +
            "\"state\": \"My State\"," +
            "\"country\": \"My Country\"," +
            "\"alternative_name\": [\"My Alternative Name 1\", \"My Alternative Name 2\"]"+
            "}" +
            "}";

    String expectedJson = json(certificateSecret);

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/my-cert", requestJson);

    mockMvc.perform(requestBuilder)
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
            .andExpect(content().json(expectedJson));

    assertThat(secretRepository.findOneByName("my-cert").generateView(), BeanMatchers.theSameAs(certificateSecret));
  }


  @Test
  public void getReturnsNotFoundWhenSecretDoesNotExist() throws Exception {
    String badResponse = "{\"error\": \"Secret not found. Please validate your input and retry your request.\"}";

    mockMvc.perform(get("/api/v1/data/whatever"))
        .andExpect(status().isNotFound())
        .andExpect(content().json(badResponse));
  }

  @Test
  public void deleteReturnsNotFoundWhenSecretDoesNotExist() throws Exception {
    String badResponse = "{\"error\": \"Secret not found. Please validate your input and retry your request.\"}";

    mockMvc.perform(delete("/api/v1/data/whatever"))
        .andExpect(status().isNotFound())
        .andExpect(content().json(badResponse));
  }

  @Test
  public void invalidPutWithEmptyJSONShouldReturnBadRequest() throws Exception {
    String badResponseJson = "{\"error\": \"The request does not include a valid type. Please validate your input and retry your request.\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier", "{}");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().json(badResponseJson));
  }

  @Test
  public void invalidPutWithNoBodyShouldReturnBadRequest() throws Exception {
    String badResponseJson = "{\"error\": \"The request does not include a valid type. Please validate your input and retry your request.\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier", "");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().json(badResponseJson));
  }

  @Test
  public void invalidPutWithMissingTypeShouldReturnBadRequest() throws Exception {
    String badResponseJson = "{\"error\": \"The request does not include a valid type. Please validate your input and" +
        " retry your request.\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier",
        "{\"value\":\"my-secret\"}");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().json(badResponseJson));
  }

  @Test
  public void invalidPutWithMissingValueShouldReturnBadRequest() throws Exception {
    String badResponseJson = "{\"error\": \"A non-empty value must be specified for the credential. Please validate and retry your request.\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier",
        "{\"type\":\"value\"}");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().json(badResponseJson));
  }

  @Test
  public void invalidPutWithNoTypeShouldReturnBadRequest() throws Exception {
    String badResponseJson = "{\"error\": \"The request does not include a valid type. Please validate your input and" +
        " retry your request.\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier",
        "{\"value\":\"my-secret\"}");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().json(badResponseJson));
  }

  @Test
  public void invalidPutWithUnsupportedTypeShouldReturnBadRequest() throws Exception {
    String badResponseJson = "{\"error\": \"The request does not include a valid type. Please validate your input and retry your request.\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier",
        "{\"type\":\"foo\", \"value\":\"my-secret\"}");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().json(badResponseJson));
  }

  @Test
  public void generateSecretReturnsBadRequestWhenBodyEmpty() throws Exception {
    String badResponse = "{\"error\": \"The request does not include a valid type. Please validate your input and retry your request.\"}";

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/secret-identifier", "");
    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().json(badResponse));
  }

  @Test
  public void generateSecretReturnsBadRequestWhenMissingRequiredCertificateParameter() throws Exception {
    String badResponse = "{\"error\": \"Organization, state and country are required to generate a certificate. Please add these parameters and retry your request.\"}";

    String requestJson = "{" +
        "\"type\":\"certificate\"," +
        "\"parameters\":{" +
        "\"organization\": \"organization.io\"," +
        "\"country\": \"My Country\"" +
        "}" +
        "}";

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/secret-identifier", requestJson);
    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().json(badResponse));
  }

  @Test
  public void generateSecretReturnsBadRequestWhenJsonEmpty() throws Exception {
    String badResponseJson = "{\"error\": \"The request does not include a valid type. Please validate your input and retry your request.\"}";

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/secret-identifier", "{}");
    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().json(badResponseJson));
  }

  @Test
  public void putSecretReturnsBadRequestIfTypeIsNotKnown() throws Exception {
    String badResponse = "{\"error\": \"The request does not include a valid type. Please validate your input and retry your request.\"}";

    String requestJson = "{\"type\":\"foo\",\"value\":\"secret contents\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier", requestJson);
    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().json(badResponse));
  }

  @Test
  public void canStoreNullsInCertificateSecret() throws Exception {
    permutateTwoEmptiesTest(null);
  }

  @Test
  public void canStoreEmptyStringsAsNullsInCertificateSecret() throws Exception {
    permutateTwoEmptiesTest("");
  }

  private void permutateTwoEmptiesTest(String emptyValue) throws Exception {
    new PutCertificateSimulator(emptyValue, emptyValue, "my-priv")
        .setExpectation(200)
        .execute();

    new PutCertificateSimulator("my-ca", emptyValue, emptyValue)
        .setExpectation(200)
        .execute();

    new PutCertificateSimulator(emptyValue, "my-pub", emptyValue)
        .setExpectation(200)
        .execute();
  }

  @Test
  public void invalidPutWithAllThreeCertificateFieldsSetToNull() throws Exception {
    String badResponseJson = "{\"error\": \"At least one certificate type must be set. Please validate your input and retry your request.\"}";
    new PutCertificateSimulator(null, null, null)
        .setExpectation(400, badResponseJson)
        .execute();
  }

  @Test
  public void invalidPutWithAllThreeCertificateFieldsSetToEmptyString() throws Exception {
    String badResponseJson = "{\"error\": \"At least one certificate type must be set. Please validate your input and retry your request.\"}";
    new PutCertificateSimulator("", "", "")
        .setExpectation(400, badResponseJson)
        .execute();
  }

  @Test
  public void contentNegotiationAndPathMatchingAreDisabled() throws Exception{
    doPutValue("test", "abc");
    doPutValue("test.foo", "def");
    mockMvc.perform(get("/api/v1/data/test"))
        .andExpect(status().isOk())
        .andExpect(content().json("{\"type\":\"value\",\"value\":\"abc\"}"));
  }

  private void doPutValue(String secretName, String secretValue) throws Exception {
    String requestJson = "{\"type\":\"value\",\"value\":\"" + secretValue + "\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/" + secretName, requestJson);
    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk());
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
    return objectMapper.writeValueAsString(o);
  }

  private void freeze() {
    frozenTime = LocalDateTime.now(utc);
    currentTimeProvider.setOverrideTime(frozenTime);
  }

  class PutCertificateSimulator {
    private final String ca;
    private final String pub;
    private final String priv;
    private int statusCode;
    private String badResponseJson;

    public PutCertificateSimulator(String ca, String pub, String priv) {
      this.ca = ca;
      this.pub = pub;
      this.priv = priv;
    }

    public void execute() throws Exception {
      CertificateSecret certificateSecretForRequest = new CertificateSecret(ca, pub, priv);
      CertificateSecret certificateSecretForResponse = new CertificateSecret(
          transformEmptyToNull(ca),
          transformEmptyToNull(pub),
          transformEmptyToNull(priv))
          .setUpdatedAt(frozenTime);

      String requestJson = json(certificateSecretForRequest);

      boolean isHttpOk = statusCode == 200;
      ResultMatcher expectedStatus = isHttpOk ? status().isOk() : status().isBadRequest();
      ResultActions result = mockMvc.perform(putRequestBuilder("/api/v1/data/whatever", requestJson)).andExpect(expectedStatus);
      NamedSecret certificateFromDb = secretRepository.findOneByName("whatever");

      if (isHttpOk) {
        assertThat(certificateFromDb.generateView(), BeanMatchers.theSameAs(certificateSecretForResponse));
      } else {
        assertNull(certificateFromDb);
        result.andExpect(content().json(badResponseJson));
      }
    }

    private String transformEmptyToNull(String param) {
      return "".equals(param) ? null : param;
    }

    public PutCertificateSimulator setExpectation(int statusCode) {
      return setExpectation(statusCode, null);
    }

    public PutCertificateSimulator setExpectation(int statusCode, String badResponseJson) {
      this.statusCode = statusCode;
      this.badResponseJson = badResponseJson;
      return this;
    }
  }
}
