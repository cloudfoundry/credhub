package io.pivotal.security.controller.v1.credential;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.reset;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.audit.EventAuditLogService;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.ValueCredential;
import io.pivotal.security.helper.AuditingHelper;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(Spectrum.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class CredentialsControllerErrorHandlingSetTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  private Encryptor encryptor;

  @SpyBean
  EventAuditLogService eventAuditLogService;

  @Autowired
  RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  EventAuditRecordRepository eventAuditRecordRepository;

  @SpyBean
  CredentialDataService credentialDataService;

  private AuditingHelper auditingHelper;

  private MockMvc mockMvc;

  private final String credentialName = "/my-namespace/secretForSetTest/credential-name";

  final String credentialValue = "credential-value";

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();

      auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
    });

    describe("setting a credential", () -> {
      describe("via parameter in request body", () -> {
        describe("error handling", () -> {
          it("returns 400 when the handler raises an exception", () -> {
            ValueCredential valueCredential = new ValueCredential(credentialName);
            valueCredential.setEncryptor(encryptor);
            valueCredential.setValue(credentialValue);
            doReturn(
                valueCredential
            ).when(credentialDataService).findMostRecent(credentialName);

            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"password\"," +
                    "  \"name\":\"" + credentialName + "\"," +
                    "  \"value\":\"some password\"" +
                    "}");

            mockMvc.perform(put)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(
                    jsonPath("$.error")
                        .value("The credential type cannot be modified. " +
                            "Please delete the credential if you wish to create it with " +
                            "a different type.")
                );
          });

          it("returns 400 when name is empty", () -> {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"password\"," +
                    "  \"name\":\"\"," +
                    "  \"value\":\"some password\"" +
                    "}");

            mockMvc.perform(put)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(
                    jsonPath("$.error")
                        .value("A credential name must be provided. " +
                            "Please validate your input and retry your request.")
                );
          });

          it("returns 400 when name contains double slash (//)", () -> {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"password\"," +
                    "  \"name\":\"pass//word\"," +
                    "  \"value\":\"some password\"" +
                    "}");

            mockMvc.perform(put)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(
                    jsonPath("$.error")
                        .value("A credential name cannot end with a '/' " +
                            "character or contain '//'. Credential names should be in the " +
                            "form of /[path]/[name] or [path]/[name]. Please update and retry " +
                            "your request.")
                );
          });

          it("returns 400 when name ends with a slash", () -> {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"password\"," +
                    "  \"name\":\"password/\"," +
                    "  \"value\":\"some password\"" +
                    "}");

            mockMvc.perform(put)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(
                    jsonPath("$.error")
                        .value("A credential name cannot end with a '/' character " +
                            "or contain '//'. Credential names should be in the form " +
                            "of /[path]/[name] or [path]/[name]. Please update and retry " +
                            "your request.")
                );
          });

          it("returns 400 when name is missing", () -> {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"password\"," +
                    "  \"value\":\"some password\"" +
                    "}");

            mockMvc.perform(put)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(
                    jsonPath("$.error")
                        .value("A credential name must be provided. " +
                            "Please validate your input and retry your request.")
                );
          });

          it("returns 400 when type is missing", () -> {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"name\":\"some-name\"," +
                    "  \"value\":\"some password\"" +
                    "}");

            mockMvc.perform(put)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(
                    jsonPath("$.error")
                        .value("The request does not include a valid type. " +
                            "Valid values include 'value', 'json', 'password', 'user', 'certificate', " +
                            "'ssh' and 'rsa'.")
                );
          });

          it("returns 400 when type is blank", () -> {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"\"," +
                    "  \"name\":\"some-name\"," +
                    "  \"value\":\"some password\"" +
                    "}");

            mockMvc.perform(put)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(
                    jsonPath("$.error")
                        .value("The request does not include a valid type. " +
                            "Valid values include 'value', 'json', 'password', 'user', 'certificate', " +
                            "'ssh' and 'rsa'.")
                );
          });

          it("returns 400 when type unknown", () -> {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"moose\"," +
                    "  \"name\":\"some-name\"," +
                    "  \"value\":\"some password\"" +
                    "}");

            mockMvc.perform(put)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(
                    jsonPath("$.error")
                        .value("The request does not include a valid type. " +
                            "Valid values include 'value', 'json', 'password', 'user', 'certificate', " +
                            "'ssh' and 'rsa'.")
                );
          });

          it("returns 400 when value is missing", () -> {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"name\":\"some-name\"," +
                    "  \"type\":\"password\"" +
                    "}");

            mockMvc.perform(put)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(
                    jsonPath("$.error")
                        .value("A non-empty value must be specified for the " +
                            "credential. Please validate and retry your request.")
                );
          });

          it("returns 400 when password is missing for user", () -> {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
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

            mockMvc.perform(put)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(
                    jsonPath("$.error").value(expectedError)
                );
          });

          it("returns an error message when an unknown top-level key is present", () -> {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"value\"," +
                    "  \"name\":\"" + credentialName + "\"," +
                    "  \"response_error\":\"invalid key\"," +
                    "  \"value\":\"THIS REQUEST some value\"" +
                    "}");

            mockMvc.perform(put)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(
                    jsonPath("$.error")
                        .value("The request includes an unrecognized parameter " +
                            "'response_error'. Please update or remove this parameter and " +
                            "retry your request.")
                );
          });

          it("returns an error message when the input JSON is malformed", () -> {
            final String malformedJson = "{" +
                "  \"type\":\"value\"," +
                "  \"name\":\"" + credentialName + "\"" +
                "  \"response_error\":\"invalid key\"" +
                "  \"value\":\"THIS REQUEST some value\"" +
                "}";
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(malformedJson);

            mockMvc.perform(put)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(
                    jsonPath("$.error")
                        .value("The request could not be fulfilled because the " +
                            "request path or body did not meet expectation. Please check the " +
                            "documentation for required formatting and retry your request.")
                );
          });

          describe("when malformed json is sent", () -> {
            it("returns a nice error message", () -> {
              final String malformedJson = "{" +
                  "  \"type\":\"value\"" +
                  "  \"name\":\"" + credentialName + "\"" +
                  "  \"value\":\"[]\"" +
                  "}";
              final MockHttpServletRequestBuilder post = put("/api/v1/data")
                  .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                  .accept(APPLICATION_JSON)
                  .contentType(APPLICATION_JSON)
                  .content(malformedJson);

              this.mockMvc.perform(post).andExpect(status().isBadRequest())
                  .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                  .andExpect(
                      jsonPath("$.error",
                          equalTo("The request could not be fulfilled because the " +
                              "request path or body did not meet expectation. Please check " +
                              "the documentation for required formatting and retry your " +
                              "request."))
                  );
            });

            it("returns a nice error message for different kinds of payloads", () -> {
              final String malformedJson = "{" +
                  "  \"type\":\"value\"," +
                  "  \"name\":\"" + credentialName + "\"," +
                  "  \"value\":\"[\"some\" \"key\"]\"" +
                  "}";
              final MockHttpServletRequestBuilder post = put("/api/v1/data")
                  .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                  .accept(APPLICATION_JSON)
                  .contentType(APPLICATION_JSON)
                  .content(malformedJson);

              this.mockMvc.perform(post).andExpect(status().isBadRequest())
                  .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                  .andExpect(
                      jsonPath(
                          "$.error",
                          equalTo("The request could not be fulfilled " +
                              "because the request path or body did not meet " +
                              "expectation. Please check the documentation for " +
                              "required formatting and retry your request."))
                  );
            });
          });
        });
      });
    });

    describe("updating a credential", () -> {
      beforeEach(() -> {
        putCredentialInDatabase(credentialName, "original value");
      });

      it("should return 400 when trying to update a credential with a mismatching type", () -> {
        final MockHttpServletRequestBuilder put = put("/api/v1/data")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"password\"," +
                "  \"name\":\"" + credentialName.toUpperCase() + "\"," +
                "  \"value\":\"my-password\"," +
                "  \"overwrite\":true" +
                "}");
        final String errorMessage = "The credential type cannot be modified. " +
            "Please delete the credential if you wish to create it with a different type.";
        mockMvc.perform(put)
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value(errorMessage));

        auditingHelper.verifyAuditing(
            CREDENTIAL_UPDATE,
            credentialName.toUpperCase(),
            "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
            "/api/v1/data",
            400
        );
      });
    });
  }

  private void putCredentialInDatabase(String name, String value) throws Exception {
    final MockHttpServletRequestBuilder put = put("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"value\"," +
            "  \"name\":\"" + name + "\"," +
            "  \"value\":\"" + value + "\"" +
            "}");

    mockMvc.perform(put);

    credentialDataService.findMostRecent(name).getUuid();
    reset(credentialDataService);
  }
}
