package io.pivotal.security.controller.v1;

import io.pivotal.security.controller.HtmlUnitTestBase;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.model.*;
import io.pivotal.security.repository.SecretStore;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.function.Consumer;

import static io.pivotal.security.matcher.ReflectiveEqualsMatcher.reflectiveEqualTo;
import static junit.framework.TestCase.assertNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Transactional
public class SecretsControllerTest extends HtmlUnitTestBase {

  @Autowired
  private HttpMessageConverter mappingJackson2HttpMessageConverter;

  @Autowired
  private SecretStore secretStore;

  @InjectMocks
  @Autowired
  private SecretsController secretsController;

  @Mock
  private SecretGenerator secretGenerator;

  @Before
  public void setUp() {
    super.setUp();
    MockitoAnnotations.initMocks(this);
  }

  @Test
  public void validPutSecret() throws Exception {
    String requestJson = "{\"type\":\"value\",\"value\":\"secret contents\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(requestJson));

    Assert.assertThat(secretStore.getSecret("secret-identifier"), reflectiveEqualTo(new StringSecret("secret contents")));
  }

  @Test
  public void validGetStringSecret() throws Exception {
    StringSecret stringSecret = new StringSecret("stringSecret contents");

    secretStore.set("whatever", stringSecret);

    String expectedJson = json(stringSecret);

    mockMvc.perform(get("/api/v1/data/whatever"))
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));
  }

  @Test
  public void validGetCertificateSecret() throws Exception {
    CertificateSecret certificateSecret = new CertificateSecret("get-ca", "get-pub", "get-priv");

    secretStore.set("whatever", certificateSecret);

    String expectedJson = json(certificateSecret);

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
    Assert.assertThat(secretStore.getSecret("secret-identifier"), reflectiveEqualTo(certificateSecret));
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
    StringSecret stringSecret = new StringSecret("stringSecret contents");

    secretStore.set("whatever", stringSecret);

    mockMvc.perform(get("/api/v2/data/whatever"))
        .andExpect(status().isNotFound());
  }

  @Test
  public void validDeleteSecret() throws Exception {
    StringSecret stringSecret = new StringSecret("super stringSecret do not tell");

    secretStore.set("whatever", stringSecret);

    mockMvc.perform(delete("/api/v1/data/whatever"))
        .andExpect(status().isOk());

    Assert.assertNull(secretStore.getSecret("whatever"));
  }

  @Test
  public void generateSecretWithNoParameters() throws Exception {
    SecretParameters parameters = new SecretParameters();
    when(secretGenerator.generateSecret(parameters)).thenReturn("very-secret");

    StringSecret expectedStringSecret = new StringSecret("very-secret");
    String expectedJson = json(expectedStringSecret);

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/my-secret", "{\"type\":\"value\"}");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));

    assertThat(secretStore.getSecret("my-secret"), reflectiveEqualTo(expectedStringSecret));
  }

  @Test
  public void generateSecretWithEmptyParameters() throws Exception {
    SecretParameters parameters = new SecretParameters();
    when(secretGenerator.generateSecret(parameters)).thenReturn("very-secret");

    StringSecret expectedStringSecret = new StringSecret("very-secret");
    String expectedJson = json(expectedStringSecret);

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/my-secret", "{\"type\":\"value\",\"parameters\":{}}");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));

    assertThat(secretStore.getSecret("my-secret"), reflectiveEqualTo(expectedStringSecret));
  }

  @Test
  public void generateSecretWithParameters() throws Exception {
    SecretParameters expectedParameters = new SecretParameters();
    expectedParameters.setExcludeSpecial(true);
    expectedParameters.setExcludeNumber(true);
    expectedParameters.setExcludeUpper(true);
    expectedParameters.setLength(42);

    when(secretGenerator.generateSecret(expectedParameters)).thenReturn("long-secret");

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

    assertThat(secretStore.getSecret("my-secret"), reflectiveEqualTo(expectedStringSecret));
  }

  @Test
  public void generateSecretWithDifferentParameters() throws Exception {
    SecretParameters expectedParameters = new SecretParameters();
    expectedParameters.setExcludeSpecial(true);
    expectedParameters.setExcludeLower(true);
    expectedParameters.setLength(42);

    when(secretGenerator.generateSecret(expectedParameters)).thenReturn("long-secret");

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

    assertThat(secretStore.getSecret("my-secret"), reflectiveEqualTo(expectedStringSecret));
  }

  @Test
  public void generateSecretWithAllExcludeParameters() throws Exception {
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
    doTwoEmptiesTest(null);
  }

  @Test
  public void canStoreEmptyStringsAsNullsInCertificateSecret() throws Exception {
    doTwoEmptiesTest("");
  }

  private void doTwoEmptiesTest(String emptyValue) throws Exception {
    doTest((body) -> {
      body.setCa(emptyValue);
      body.setPub(emptyValue);
    }, (body) -> {
      body.setCa(null);
      body.setPub(null);
    }, status().isOk(), true);
    doTest((body) -> {
      body.setPub(emptyValue);
      body.setPriv(emptyValue);
    }, (body) -> {
      body.setPub(null);
      body.setPriv(null);
    }, status().isOk(), true);
    doTest((body) -> {
      body.setCa(emptyValue);
      body.setPriv(emptyValue);
    }, (body) -> {
      body.setCa(null);
      body.setPriv(null);
    }, status().isOk(), true);
  }

  @Test
  public void invalidPutWithAllThreeCertificateFieldsSetToNull() throws Exception {
    doTest((body) -> {
      body.setCa(null);
      body.setPub(null);
      body.setPriv(null);
    }, (body) -> {}, status().isBadRequest(), false);
  }

  @Test
  public void invalidPutWithAllThreeCertificateFieldsSetToEmptyString() throws Exception {
    doTest((body) -> {
      body.setCa("");
      body.setPub("");
      body.setPriv("");
    }, (body) -> {}, status().isBadRequest(), false);
  }

  public void doTest(Consumer<CertificateBody> requestMutator, Consumer<CertificateBody> responseMutator, ResultMatcher expectedStatus, boolean checkResult) throws Exception {
    CertificateSecret certificateSecretForRequest = new CertificateSecret("get-ca", "get-pub", "get-priv");
    CertificateSecret certificateSecretForResponse = new CertificateSecret("get-ca", "get-pub", "get-priv");
    requestMutator.accept(certificateSecretForRequest.getCertificateBody());
    responseMutator.accept(certificateSecretForResponse.getCertificateBody());

    String requestJson = json(certificateSecretForRequest);

    mockMvc.perform(putRequestBuilder("/api/v1/data/whatever", requestJson)).andExpect(expectedStatus);
    Secret certificateFromDb = secretStore.getSecret("whatever");
    if (checkResult) {
      assertThat(certificateFromDb, reflectiveEqualTo(certificateSecretForResponse));
    } else {
      assertNull(certificateFromDb);
    }
  }

  // TODO when all three certificate components are null, that's a 400. Output suitable error message as well.

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

  protected String json(Object o) throws IOException {
    MockHttpOutputMessage mockHttpOutputMessage = new MockHttpOutputMessage();
    this.mappingJackson2HttpMessageConverter.write(
        o, MediaType.APPLICATION_JSON, mockHttpOutputMessage);
    return mockHttpOutputMessage.getBodyAsString();
  }
}
