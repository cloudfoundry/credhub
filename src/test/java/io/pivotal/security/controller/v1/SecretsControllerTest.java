package io.pivotal.security.controller.v1;

import io.pivotal.security.controller.HtmlUnitTestBase;
import io.pivotal.security.entity.Secret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.model.SecretParameters;
import io.pivotal.security.repository.SecretRepository;
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
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.RequestBuilder;

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

public class SecretsControllerTest extends HtmlUnitTestBase {

  @Autowired
  private HttpMessageConverter mappingJackson2HttpMessageConverter;

  @Autowired
  private SecretRepository secretRepository;

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
  @DirtiesContext
  public void validPutSecret() throws Exception {
    String requestJson = "{\"type\":\"value\",\"value\":\"secret contents\"}";
    Secret expectedSecret = new Secret("secret contents", "value");
    String expectedJson = json(expectedSecret);

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier", requestJson);

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));

    Assert.assertEquals(secretRepository.get("secret-identifier"), expectedSecret);
  }

  @Test
  @DirtiesContext
  public void validGetSecret() throws Exception {
    Secret secret = new Secret("secret contents", "value");

    secretRepository.set("whatever", secret);

    String expectedJson = json(secret);

    mockMvc.perform(get("/api/v1/data/whatever"))
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));
  }

  @Test
  @DirtiesContext
  public void getSecretWithInvalidVersion() throws Exception {
    Secret secret = new Secret("secret contents", "value");

    secretRepository.set("whatever", secret);

    mockMvc.perform(get("/api/v2/data/whatever"))
        .andExpect(status().isNotFound());
  }

  @Test
  @DirtiesContext
  public void validDeleteSecret() throws Exception {
    Secret secret = new Secret("super secret do not tell", "value");

    secretRepository.set("whatever", secret);

    mockMvc.perform(delete("/api/v1/data/whatever"))
        .andExpect(status().isOk());

    Assert.assertNull(secretRepository.get("whatever"));
  }

  @Test
  @DirtiesContext
  public void generateSecretWithNoParameters() throws Exception {
    SecretParameters parameters = new SecretParameters();
    when(secretGenerator.generateSecret(parameters)).thenReturn("very-secret");

    Secret expectedSecret = new Secret("very-secret", "value");
    String expectedJson = json(expectedSecret);

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/my-secret", "{\"type\":\"value\"}");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));

    assertThat(secretRepository.get("my-secret"), equalTo(expectedSecret));
  }

  @Test
  @DirtiesContext
  public void generateSecretWithEmptyParameters() throws Exception {
    SecretParameters parameters = new SecretParameters();
    when(secretGenerator.generateSecret(parameters)).thenReturn("very-secret");

    Secret expectedSecret = new Secret("very-secret", "value");
    String expectedJson = json(expectedSecret);

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/my-secret", "{\"type\":\"value\",\"parameters\":{}}");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
        .andExpect(content().json(expectedJson));

    assertThat(secretRepository.get("my-secret"), equalTo(expectedSecret));
  }

  @Test
  @DirtiesContext
  public void generateSecretWithParameters() throws Exception {
    SecretParameters expectedParameters = new SecretParameters();
    expectedParameters.setExcludeSpecial(true);
    expectedParameters.setExcludeNumber(true);
    expectedParameters.setExcludeUpper(true);
    expectedParameters.setLength(42);

    when(secretGenerator.generateSecret(expectedParameters)).thenReturn("long-secret");

    Secret expectedSecret = new Secret("long-secret", "value");
    String expectedJson = json(expectedSecret);

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

    assertThat(secretRepository.get("my-secret"), equalTo(expectedSecret));
  }

  @Test
  @DirtiesContext
  public void generateSecretWithDifferentParameters() throws Exception {
    SecretParameters expectedParameters = new SecretParameters();
    expectedParameters.setExcludeSpecial(true);
    expectedParameters.setExcludeLower(true);
    expectedParameters.setLength(42);

    when(secretGenerator.generateSecret(expectedParameters)).thenReturn("long-secret");

    Secret expectedSecret = new Secret("long-secret", "value");
    String expectedJson = json(expectedSecret);

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

    assertThat(secretRepository.get("my-secret"), equalTo(expectedSecret));
  }

  @Test
  @DirtiesContext
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
    String badResponseJson = "{\"error\": \"The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier", "{}");

    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().json(badResponseJson));
  }

  @Test
  public void invalidPutWithNoBodyShouldReturnBadRequest() throws Exception {
    String badResponseJson = "{\"error\": \"The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.\"}";

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
  @DirtiesContext
  public void generateSecretReturnsBadRequestWhenBodyEmpty() throws Exception {
    String badResponse = "{\"error\": \"The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.\"}";

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/secret-identifier", "");
    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().json(badResponse));
  }

  @Test
  @DirtiesContext
  public void generateSecretReturnsBadRequestWhenJsonEmpty() throws Exception {
    String badResponseJson = "{\"error\": \"The request does not include a valid type. Please validate your input and retry your request.\"}";

    RequestBuilder requestBuilder = postRequestBuilder("/api/v1/data/secret-identifier", "{}");
    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().json(badResponseJson));
  }

  @Test
  @DirtiesContext
  public void putSecretReturnsBadRequestIfTypeIsNotKnown() throws Exception {
    String badResponse = "{\"error\": \"The request does not include a valid type. Please validate your input and retry your request.\"}";

    String requestJson = "{\"type\":\"foo\",\"value\":\"secret contents\"}";

    RequestBuilder requestBuilder = putRequestBuilder("/api/v1/data/secret-identifier", requestJson);
    mockMvc.perform(requestBuilder)
        .andExpect(status().isBadRequest())
        .andExpect(content().json(badResponse));
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

  protected String json(Object o) throws IOException {
    MockHttpOutputMessage mockHttpOutputMessage = new MockHttpOutputMessage();
    this.mappingJackson2HttpMessageConverter.write(
        o, MediaType.APPLICATION_JSON, mockHttpOutputMessage);
    return mockHttpOutputMessage.getBodyAsString();
  }
}
