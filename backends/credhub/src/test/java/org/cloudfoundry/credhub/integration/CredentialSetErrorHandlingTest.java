package org.cloudfoundry.credhub.integration;

import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
import org.cloudfoundry.credhub.utils.DatabaseUtilities;
import org.cloudfoundry.credhub.utils.TestConstants;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.helpers.RequestHelper.setPassword;
import static org.cloudfoundry.credhub.utils.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.utils.SpringUtilities.activeProfilesString;
import static org.cloudfoundry.credhub.utils.SpringUtilities.unitTestPostgresProfile;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
public class CredentialSetErrorHandlingTest {

  private final String CREDENTIAL_NAME = "/my-namespace/secretForErrorHandlingSetTest/credential-name";

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  @Before
  public void setUp() {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();
  }

  @Test
  public void whenTheTypeChanges_returns400() throws Exception {
    setPassword(mockMvc, CREDENTIAL_NAME, "some password", ALL_PERMISSIONS_TOKEN);

    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"type\":\"value\"," +
        "  \"name\":\"" + CREDENTIAL_NAME + "\"," +
        "  \"value\":\"some password\"" +
        "}");

    final String expectedError = "The credential type cannot be modified. Please delete the credential if you wish to create it with a different type.";
    mockMvc.perform(request)
      .andExpect(status().isBadRequest())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenTheNameIsEmpty_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"type\":\"password\"," +
        "  \"name\":\"\"," +
        "  \"value\":\"some password\"" +
        "}");

    final String expectedError = "A credential name must be provided. Please validate your input and retry your request.";
    mockMvc.perform(request)
      .andExpect(status().isBadRequest())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenNameIsMissing_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"type\":\"password\"," +
        "  \"value\":\"some password\"" +
        "}");

    final String expectedError = "A credential name must be provided. Please validate your input and retry your request.";
    mockMvc.perform(request)
      .andExpect(status().isBadRequest())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenNameHasDoubleSlash_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"type\":\"password\"," +
        "  \"name\":\"pass//word\"," +
        "  \"value\":\"some password\"" +
        "}");

    final String expectedError = "A credential name cannot end with a '/' character or contain '//'. Credential names should be in the form of /[path]/[name] or [path]/[name]. Please update and retry your request.";
    mockMvc.perform(request)
      .andExpect(status().isBadRequest())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenNameEndsWithSlash_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"type\":\"password\"," +
        "  \"name\":\"password/\"," +
        "  \"value\":\"some password\"" +
        "}");

    final String expectedError = "A credential name cannot end with a '/' character or contain '//'. Credential names should be in the form of /[path]/[name] or [path]/[name]. Please update and retry your request.";
    mockMvc.perform(request)
      .andExpect(status().isBadRequest())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenTypeIsMissing_returns422() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"name\":\"some-name\"," +
        "  \"value\":\"some password\"" +
        "}");

    final String expectedError = "The request does not include a valid type. Valid values include 'value', 'json', 'password', 'user', 'certificate', 'ssh' and 'rsa'.";
    mockMvc.perform(request)
      .andExpect(status().isUnprocessableEntity())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenTypeIsEmpty_returns422() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"type\":\"\"," +
        "  \"name\":\"some-name\"," +
        "  \"value\":\"some password\"" +
        "}");

    final String expectedError = "The request does not include a valid type. Valid values include 'value', 'json', 'password', 'user', 'certificate', 'ssh' and 'rsa'.";
    mockMvc.perform(request)
      .andExpect(status().isUnprocessableEntity())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenTypeIsInvalid_returns422() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"type\":\"moose\"," +
        "  \"name\":\"some-name\"," +
        "  \"value\":\"some password\"" +
        "}");

    final String expectedError = "The request does not include a valid type. Valid values include 'value', 'json', 'password', 'user', 'certificate', 'ssh' and 'rsa'.";
    mockMvc.perform(request)
      .andExpect(status().isUnprocessableEntity())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenValueIsMissing_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"name\":\"some-name\"," +
        "  \"type\":\"password\"" +
        "}");

    final String expectedError = "A non-empty value must be specified for the credential. Please validate and retry your request.";
    mockMvc.perform(request)
      .andExpect(status().isBadRequest())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenAnUnknownTopLevelKeyIsPresent_returns422() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"type\":\"value\"," +
        "  \"name\":\"" + CREDENTIAL_NAME + "\"," +
        "  \"invalid_key\":\"invalid key\"," +
        "  \"value\":\"THIS REQUEST some value\"" +
        "}");

    final String expectedError = "The request includes an unrecognized parameter 'invalid_key'. Please update or remove this parameter and retry your request.";
    mockMvc.perform(request)
      .andExpect(status().isUnprocessableEntity())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenInputJsonIsMalformed_returns400() throws Exception {
    final String malformedJson = "{" +
      "  \"type\":\"value\"," +
      "  \"name\":\"" + CREDENTIAL_NAME + "\"" +
      "  \"response_error\":\"invalid key\"" +
      "  \"value\":\"THIS REQUEST some value\"" +
      "}";
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(malformedJson);

    final String expectedError = "The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.";
    mockMvc.perform(request)
      .andExpect(status().isBadRequest())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenInputJsonHasBadValue_returns400() throws Exception {
    final String malformedJson = "{" +
      "  \"type\":\"value\"," +
      "  \"name\":\"" + CREDENTIAL_NAME + "\"," +
      "  \"value\":\"[\"some\" \"key\"]\"" +
      "}";
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content(malformedJson);

    final String expectedError = "The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.";
    this.mockMvc.perform(request).andExpect(status().isBadRequest())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error", equalTo(expectedError)));
  }

  @Test
  public void givenAUserRequest_whenPasswordIsMissing_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"name\":\"some-name\"," +
        "  \"type\":\"user\"," +
        "  \"value\": {" +
        "    \"username\": \"dan\"" +
        "  }" +
        "}");
    final String expectedError = "A password value must be specified for the credential. Please validate and retry your request.";

    mockMvc.perform(request)
      .andExpect(status().isBadRequest())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void givenACertificateRequest_whenAnInvalidCaNameIsProvided_returns404() throws Exception {
    final String setJson = new ObjectMapper().writeValueAsString(
      ImmutableMap.<String, String>builder()
        .put("ca_name", "does not exist")
        .put("certificate", TestConstants.TEST_CERTIFICATE)
        .put("private_key", TestConstants.TEST_PRIVATE_KEY)
        .build());

    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"name\":\"some-name\"," +
        "  \"type\":\"certificate\"," +
        "  \"value\": " + setJson +
        "}");

    mockMvc.perform(request)
      .andExpect(status().isNotFound())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(ErrorMessages.Credential.CERTIFICATE_ACCESS));
  }

  @Test
  public void givenACertificateRequest_whenBothCaNameAndCaAreBothProvided_returns400() throws Exception {
    final String setJson = new ObjectMapper().writeValueAsString(
      ImmutableMap.<String, String>builder()
        .put("ca_name", "CA_NAME")
        .put("ca", TestConstants.TEST_CA)
        .put("certificate", TestConstants.TEST_CERTIFICATE)
        .put("private_key", TestConstants.TEST_PRIVATE_KEY)
        .build());

    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"name\":\"some-name\"," +
        "  \"type\":\"certificate\"," +
        "  \"value\": " + setJson +
        "}");
    final String expectedError = "Only one of the values 'ca_name' and 'ca' may be provided. Please update and retry your request.";

    mockMvc.perform(request)
      .andExpect(status().isBadRequest())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void givenAPayloadThatExceedsTheMaximumSize_returnsA413() throws Exception {
    if (System.getProperty(activeProfilesString).contains(unitTestPostgresProfile)) {
      return;
    }

    final byte[] exceedsMaxBlobStoreSizeBytes = DatabaseUtilities.Companion.getExceedsMaxBlobStoreSizeBytes();
    final String exceedsMaxBlobStoreSizeValue = Base64.getEncoder().encodeToString(exceedsMaxBlobStoreSizeBytes);

    final MockHttpServletRequestBuilder request = put("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{" +
        "  \"type\":\"value\"," +
        "  \"name\":\"foo\"," +
        "  \"value\":\"" + exceedsMaxBlobStoreSizeValue + "\"" +
        "}");

    final String expectedError = "Value exceeds the maximum size.";
    mockMvc.perform(request)
      .andExpect(status().isPayloadTooLarge())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }
}
