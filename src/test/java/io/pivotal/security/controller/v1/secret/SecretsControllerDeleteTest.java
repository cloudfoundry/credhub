package io.pivotal.security.controller.v1.secret;


import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.util.ExceptionThrowingFunction;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_DELETE;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuditLogTestHelper.resetAuditLogMock;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerDeleteTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  SecretsController subject;

  @SpyBean
  AuditLogService auditLogService;

  @SpyBean
  SecretDataService secretDataService;

  private MockMvc mockMvc;

  private final String secretName = "/my-namespace/subTree/secret-name";

  private ResultActions response;

  private AuditRecordBuilder auditRecordBuilder;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();

      auditRecordBuilder = new AuditRecordBuilder();
      resetAuditLogMock(auditLogService, auditRecordBuilder);
    });

    describe("#delete", () -> {
      describe("error handling", () -> {
        it("should return NOT_FOUND when there is no secret with that name", () -> {
          final MockHttpServletRequestBuilder delete = delete("/api/v1/data?name=invalid_name")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON);

          mockMvc.perform(delete)
              .andExpect(status().isNotFound())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(
                  jsonPath("$.error")
                      .value("Credential not found. " +
                          "Please validate your input and retry your request.")
              );
        });

        it("should return an error when name is empty", () -> {
          final MockHttpServletRequestBuilder delete = delete("/api/v1/data?name=")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON);

          mockMvc.perform(delete)
              .andExpect(status().isBadRequest())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(
                  jsonPath("$.error")
                      .value("The query parameter name is required for this request.")
              );
        });

        it("should return an error when name is missing", () -> {
          final MockHttpServletRequestBuilder delete = delete("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON);

          mockMvc.perform(delete)
              .andExpect(status().is4xxClientError())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(
                  jsonPath("$.error")
                      .value("The query parameter name is required for this request.")
              );
        });
      });

      describe("when there is one secret with the name (case-insensitive)", () -> {
        beforeEach(() -> {
          doReturn(1L).when(secretDataService).delete(secretName.toUpperCase());
          doReturn(new NamedValueSecret())
              .when(secretDataService)
              .findMostRecent(secretName.toUpperCase());
          response = mockMvc.perform(delete("/api/v1/data?name=" + secretName.toUpperCase())
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
          );
        });

        it("should return a 204 status", () -> {
          response.andExpect(status().isNoContent());
        });

        it("asks data service to remove it from storage", () -> {
          verify(secretDataService, times(1)).delete(secretName.toUpperCase());
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(isA(ExceptionThrowingFunction.class));
          assertThat(auditRecordBuilder.getOperationCode(), equalTo(CREDENTIAL_DELETE));
          assertThat(auditRecordBuilder.getCredentialName(), equalTo(secretName.toUpperCase()));
        });
      });

      describe("when there are multiple secrets with that name", () -> {
        beforeEach(() -> {
          NamedValueSecret value1 = new NamedValueSecret(secretName);
          value1.setEncryptedValue("value1".getBytes());
          NamedValueSecret value2 = new NamedValueSecret(secretName);
          value2.setEncryptedValue("value2".getBytes());
          doReturn(2L).when(secretDataService).delete(secretName);
          doReturn(new NamedValueSecret()).when(secretDataService).findMostRecent(secretName);

          response = mockMvc.perform(delete("/api/v1/data?name=" + secretName)
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
          );
        });

        it("should succeed", () -> {
          response.andExpect(status().isNoContent());
        });

        it("should remove them all from the database", () -> {
          verify(secretDataService, times(1)).delete(secretName);
        });

        it("persists a single audit entry", () -> {
          verify(auditLogService).performWithAuditing(isA(ExceptionThrowingFunction.class));
          assertThat(auditRecordBuilder.getOperationCode(), equalTo(CREDENTIAL_DELETE));
          assertThat(auditRecordBuilder.getCredentialName(), equalTo(secretName));
        });
      });

      describe("name can come as a request parameter", () -> {
        beforeEach(() -> {
          NamedValueSecret value1 = new NamedValueSecret(secretName);
          value1.setEncryptedValue("value1".getBytes());
          NamedValueSecret value2 = new NamedValueSecret(secretName);
          value2.setEncryptedValue("value2".getBytes());
          doReturn(2L).when(secretDataService).delete(secretName.toUpperCase());
          doReturn(new NamedValueSecret())
              .when(secretDataService)
              .findMostRecent(secretName.toUpperCase());
        });

        it("can delete when the name is a query param", () -> {
          mockMvc.perform(delete("/api/v1/data?name=" + secretName.toUpperCase())
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN))
              .andExpect(status().isNoContent());

          verify(secretDataService, times(1)).delete(secretName.toUpperCase());
        });

        it("handles missing name parameter", () -> {
          mockMvc.perform(delete("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN))
              .andExpect(status().isBadRequest());
        });

        it("handles empty name", () -> {
          mockMvc.perform(delete("/api/v1/data?name=")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN))
              .andExpect(status().isBadRequest());
        });
      });
    });
  }
}
