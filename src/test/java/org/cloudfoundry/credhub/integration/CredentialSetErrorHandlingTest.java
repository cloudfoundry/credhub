package org.cloudfoundry.credhub.integration;

import com.google.common.collect.ImmutableMap;
import net.minidev.json.JSONObject;
import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.helper.AuditingHelper;
import org.cloudfoundry.credhub.repository.EventAuditRecordRepository;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.util.TestConstants;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static org.cloudfoundry.credhub.helper.RequestHelper.setPassword;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialSetErrorHandlingTest {

  private final String CREDENTIAL_NAME = "/my-namespace/secretForErrorHandlingSetTest/credential-name";
  private final String CREDENTIAL_VALUE = "credential-value";

  @Autowired
  private WebApplicationContext webApplicationContext;

  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  private AuditingHelper auditingHelper;
  private MockMvc mockMvc;

  @Before
  public void setUp() {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
  }

  @Test
  public void whenTheTypeChanges_returns400() throws Exception {
    setPassword(mockMvc, CREDENTIAL_NAME, "some password", CredentialWriteMode.OVERWRITE.mode);

    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"value\"," +
            "  \"name\":\"" + CREDENTIAL_NAME + "\"," +
            "  \"value\":\"some password\"" +
            "}");

    String expectedError = "The credential type cannot be modified. Please delete the credential if you wish to create it with a different type.";
    mockMvc.perform(request)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenTheTypeChanges_auditsTheFailure() throws Exception {
    final MockHttpServletRequestBuilder setRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"value\"," +
            "  \"name\":\"" + CREDENTIAL_NAME + "\"," +
            "  \"value\":\"" + CREDENTIAL_VALUE + "\"" +
            "}");

    mockMvc.perform(setRequest).andDo(print());

    final MockHttpServletRequestBuilder updateRequest = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"password\"," +
            "  \"name\":\"" + CREDENTIAL_NAME.toUpperCase() + "\"," +
            "  \"value\":\"my-password\"," +
            "  \"overwrite\":true" +
            "}");
    final String errorMessage = "The credential type cannot be modified. Please delete the credential if you wish to create it with a different type.";
    mockMvc.perform(updateRequest)
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").value(errorMessage));

    auditingHelper.verifyAuditing(
        CREDENTIAL_UPDATE,
        CREDENTIAL_NAME.toUpperCase(),
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/data",
        400
    );
  }

  @Test
  public void whenTheNameIsEmpty_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"password\"," +
            "  \"name\":\"\"," +
            "  \"value\":\"some password\"" +
            "}");

    String expectedError = "A credential name must be provided. Please validate your input and retry your request.";
    mockMvc.perform(request)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenNameIsMissing_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"password\"," +
            "  \"value\":\"some password\"" +
            "}");

    String expectedError = "A credential name must be provided. Please validate your input and retry your request.";
    mockMvc.perform(request)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenNameHasDoubleSlash_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"password\"," +
            "  \"name\":\"pass//word\"," +
            "  \"value\":\"some password\"" +
            "}");

    String expectedError = "A credential name cannot end with a '/' character or contain '//'. Credential names should be in the form of /[path]/[name] or [path]/[name]. Please update and retry your request.";
    mockMvc.perform(request)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenNameEndsWithSlash_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"password\"," +
            "  \"name\":\"password/\"," +
            "  \"value\":\"some password\"" +
            "}");

    String expectedError = "A credential name cannot end with a '/' character or contain '//'. Credential names should be in the form of /[path]/[name] or [path]/[name]. Please update and retry your request.";
    mockMvc.perform(request)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenTypeIsMissing_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"name\":\"some-name\"," +
            "  \"value\":\"some password\"" +
            "}");

    String expectedError = "The request does not include a valid type. Valid values include 'value', 'json', 'password', 'user', 'certificate', 'ssh' and 'rsa'.";
    mockMvc.perform(request)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenTypeIsEmpty_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"\"," +
            "  \"name\":\"some-name\"," +
            "  \"value\":\"some password\"" +
            "}");

    String expectedError = "The request does not include a valid type. Valid values include 'value', 'json', 'password', 'user', 'certificate', 'ssh' and 'rsa'.";
    mockMvc.perform(request)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenTypeIsInvalid_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"moose\"," +
            "  \"name\":\"some-name\"," +
            "  \"value\":\"some password\"" +
            "}");

    String expectedError = "The request does not include a valid type. Valid values include 'value', 'json', 'password', 'user', 'certificate', 'ssh' and 'rsa'.";
    mockMvc.perform(request)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenValueIsMissing_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"name\":\"some-name\"," +
            "  \"type\":\"password\"" +
            "}");

    String expectedError = "A non-empty value must be specified for the credential. Please validate and retry your request.";
    mockMvc.perform(request)
        .andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void whenAnUnknownTopLevelKeyIsPresent_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"value\"," +
            "  \"name\":\"" + CREDENTIAL_NAME + "\"," +
            "  \"invalid_key\":\"invalid key\"," +
            "  \"value\":\"THIS REQUEST some value\"" +
            "}");

    String expectedError = "The request includes an unrecognized parameter 'invalid_key'. Please update or remove this parameter and retry your request.";
    mockMvc.perform(request)
        .andExpect(status().isBadRequest())
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
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(malformedJson);

    String expectedError = "The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.";
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
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content(malformedJson);

    String expectedError = "The request could not be fulfilled because the request path or body did not meet expectation. Please check the documentation for required formatting and retry your request.";
    this.mockMvc.perform(request).andExpect(status().isBadRequest())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error", equalTo(expectedError)));
  }

  @Test
  public void givenAUserRequest_whenPasswordIsMissing_returns400() throws Exception {
    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
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
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca_name", "does not exist")
            .put("certificate", TestConstants.TEST_CERTIFICATE)
            .put("private_key", TestConstants.TEST_PRIVATE_KEY)
            .build());

    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"name\":\"some-name\"," +
            "  \"type\":\"certificate\"," +
            "  \"value\": " + setJson +
            "}");
    final String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    mockMvc.perform(request)
        .andExpect(status().isNotFound())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void givenACertificateRequest_whenBothCaNameAndCaAreBothProvided_returns400() throws Exception {
    final String setJson = JSONObject.toJSONString(
        ImmutableMap.<String, String>builder()
            .put("ca_name", "CA_NAME")
            .put("ca", TestConstants.TEST_CA)
            .put("certificate", TestConstants.TEST_CERTIFICATE)
            .put("private_key", TestConstants.TEST_PRIVATE_KEY)
            .build());

    final MockHttpServletRequestBuilder request = put("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
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
}
