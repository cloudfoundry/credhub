package io.pivotal.security.controller.v1;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.MockitoSpringTest;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.model.CertificateSecret;
import io.pivotal.security.model.CertificateSecretParameters;
import io.pivotal.security.model.StringSecretParameters;
import io.pivotal.security.model.StringSecret;
import io.pivotal.security.repository.InMemorySecretStore;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.ConfigurableWebApplicationContext;

import static io.pivotal.security.matcher.ReflectiveEqualsMatcher.reflectiveEqualTo;
import static junit.framework.TestCase.assertNull;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;

@Transactional
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
public class SecretsControllerTest extends MockitoSpringTest {

  @Autowired
  protected ConfigurableWebApplicationContext context;

  @Autowired
  private HttpMessageConverter mappingJackson2HttpMessageConverter;

  @Autowired
  private InMemorySecretStore secretStore;

  @InjectMocks
  @Autowired
  private SecretsController secretsController;

  @Mock
  private SecretGenerator<StringSecretParameters, StringSecret> stringSecretGenerator;

  @Mock
  private SecretGenerator<CertificateSecretParameters, CertificateSecret> certificateGenerator;

  private MockMvc mockMvc;

  @Before
  public void setUp() {
    mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
  }

  @Test
  public void validPutSecret() throws Exception {
    String requestJson = "{\"type\":\"value\",\"value\":\"secret contents\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(requestJson));

    Assert.assertThat(secretStore.getSecret("secret-identifier").convertToModel(), reflectiveEqualTo(new StringSecret("secret contents")));
  }

  @Test
  public void validGetStringSecret() throws Exception {
    NamedStringSecret stringSecret = new NamedStringSecret("whatever").setValue("stringSecret contents");

    secretStore.set(stringSecret);

    String expectedJson = json(stringSecret.convertToModel());

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

    secretStore.set(certificateSecret);

    String expectedJson = json(certificateSecret.convertToModel());

    mockMvc.perform(get("/api/v1/data/whatever"))
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));
  }

  @Test
  public void validPutCertificate() throws Exception {
    String requestJson = "{\"type\":\"certificate\",\"certificate\":{\"ca\":\"my-ca\",\"public\":\"my-pub\",\"private\":\"my-priv\"}}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(requestJson));

    CertificateSecret certificateSecret = new CertificateSecret("my-ca", "my-pub", "my-priv");
    Assert.assertThat(secretStore.getSecret("secret-identifier").convertToModel(), reflectiveEqualTo(certificateSecret));
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
  public void getSecretWithInvalidVersion() throws Exception {
    NamedStringSecret stringSecret = new NamedStringSecret("whatever").setValue("stringSecret contents");

    secretStore.set(stringSecret);

    mockMvc.perform(get("/api/v2/data/whatever"))
        .andExpect(status().isNotFound());
  }

  @Test
  public void validDeleteSecret() throws Exception {
    NamedStringSecret stringSecret = new NamedStringSecret("whatever").setValue("super stringSecret do not tell");

    secretStore.set(stringSecret);

    mockMvc.perform(delete("/api/v1/data/whatever"))
        .andExpect(status().isOk());

    Assert.assertNull(secretStore.getSecret("whatever"));
  }

  @Test
  public void generateSecretWithNoParameters() throws Exception {
    StringSecretParameters parameters = new StringSecretParameters();
    when(stringSecretGenerator.generateSecret(parameters)).thenReturn(new StringSecret("very-secret"));

    StringSecret expectedStringSecret = new StringSecret("very-secret");
    String expectedJson = json(expectedStringSecret);

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/my-secret", "{\"type\":\"value\"}");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));

    assertThat(secretStore.getSecret("my-secret").convertToModel(), reflectiveEqualTo(expectedStringSecret));
  }

  @Test
  public void generateStringSecretWithEmptyParameters() throws Exception {
    StringSecretParameters parameters = new StringSecretParameters();
    when(stringSecretGenerator.generateSecret(parameters)).thenReturn(new StringSecret("very-secret"));

    StringSecret expectedStringSecret = new StringSecret("very-secret");
    String expectedJson = json(expectedStringSecret);

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/my-secret", "{\"type\":\"value\",\"parameters\":{}}");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));

    assertThat(secretStore.getSecret("my-secret").convertToModel(), reflectiveEqualTo(expectedStringSecret));
  }

  @Test
  public void generateStringSecretWithParameters() throws Exception {
    StringSecretParameters expectedParameters = new StringSecretParameters();
    expectedParameters.setExcludeSpecial(true);
    expectedParameters.setExcludeNumber(true);
    expectedParameters.setExcludeUpper(true);
    expectedParameters.setLength(42);

    when(stringSecretGenerator.generateSecret(expectedParameters)).thenReturn(new StringSecret("long-secret"));

    StringSecret expectedStringSecret = new StringSecret("long-secret");
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

    assertThat(secretStore.getSecret("my-secret").convertToModel(), reflectiveEqualTo(expectedStringSecret));
  }

  @Test
  public void generateStringSecretWithDifferentParameters() throws Exception {
    StringSecretParameters expectedParameters = new StringSecretParameters();
    expectedParameters.setExcludeSpecial(true);
    expectedParameters.setExcludeLower(true);
    expectedParameters.setLength(42);

    when(stringSecretGenerator.generateSecret(expectedParameters)).thenReturn(new StringSecret("long-secret"));

    StringSecret expectedStringSecret = new StringSecret("long-secret");
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

    assertThat(secretStore.getSecret("my-secret").convertToModel(), reflectiveEqualTo(expectedStringSecret));
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
    CertificateSecretParameters expectedParameters = new CertificateSecretParameters();
    expectedParameters.setCommonName("My Common Name");
    expectedParameters.setOrganization("organization.io");
    expectedParameters.setOrganizationUnit("My Unit");
    expectedParameters.setLocality("My Locality");
    expectedParameters.setState("My State");
    expectedParameters.setCountry("My Country");
    expectedParameters.addAlternateName("My Alternate Name 1");
    expectedParameters.addAlternateName("My Alternate Name 2");

    CertificateSecret certificateSecret = new CertificateSecret("my-ca", "my-pub", "my-priv");
    when(certificateGenerator.generateSecret(expectedParameters)).thenReturn(certificateSecret);

    String requestJson = "{" +
            "\"type\":\"certificate\"," +
            "\"parameters\":{" +
            "\"common_name\":\"My Common Name\", " +
            "\"organization\": \"organization.io\"," +
            "\"organization_unit\": \"My Unit\"," +
            "\"locality\": \"My Locality\"," +
            "\"state\": \"My State\"," +
            "\"country\": \"My Country\"," +
            "\"alternate_name\": [\"My Alternate Name 1\", \"My Alternate Name 2\"]"+
            "}" +
            "}";

    String expectedJson = json(certificateSecret);

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/my-cert", requestJson);

    mockMvc.perform(requestBuilder)
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
            .andExpect(content().json(expectedJson));

    assertThat(secretStore.getSecret("my-cert").convertToModel(), reflectiveEqualTo(certificateSecret));
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
    MockHttpOutputMessage mockHttpOutputMessage = new MockHttpOutputMessage();
    this.mappingJackson2HttpMessageConverter.write(
        o, MediaType.APPLICATION_JSON, mockHttpOutputMessage);
    return mockHttpOutputMessage.getBodyAsString();
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
          transformEmptyToNull(priv));

      String requestJson = json(certificateSecretForRequest);

      boolean isHttpOk = statusCode == 200;
      ResultMatcher expectedStatus = isHttpOk ? status().isOk() : status().isBadRequest();
      ResultActions result = mockMvc.perform(putRequestBuilder("/api/v1/data/whatever", requestJson)).andExpect(expectedStatus);
      NamedSecret certificateFromDb = secretStore.getSecret("whatever");

      if (isHttpOk) {
        assertThat(certificateFromDb.convertToModel(), reflectiveEqualTo(certificateSecretForResponse));
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
