package io.pivotal.security.controller.v1.secret;


import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.fake.FakeAuditLogService;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.function.Supplier;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_DELETE;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerDeleteTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  SecretsController subject;

  @SpyBean
  FakeAuditLogService auditLogService;

  @SpyBean
  SecretDataService secretDataService;

  private MockMvc mockMvc;

  private final String secretName = "/my-namespace/subTree/secret-name";

  private ResultActions response;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

      resetAuditLogMock();
    });

    describe("#delete", () -> {
      describe("error handling", () -> {
        it("should return NOT_FOUND when there is no secret with that name", () -> {
          final MockHttpServletRequestBuilder delete = delete("/api/v1/data?name=invalid_name")
              .accept(APPLICATION_JSON);

          mockMvc.perform(delete)
              .andExpect(status().isNotFound())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.error").value("Credential not found. Please validate your input and retry your request."));
        });

        it("should return an error when name is empty", () -> {
          final MockHttpServletRequestBuilder delete = delete("/api/v1/data?name=")
              .accept(APPLICATION_JSON);

          mockMvc.perform(delete)
              .andExpect(status().is4xxClientError())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.error").value("A credential name must be provided. Please validate your input and retry your request."));
        });

        it("should return an error when name is missing", () -> {
          final MockHttpServletRequestBuilder delete = delete("/api/v1/data")
              .accept(APPLICATION_JSON);

          mockMvc.perform(delete)
              .andExpect(status().is4xxClientError())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.error").value("A credential name must be provided. Please validate your input and retry your request."));
        });
      });

      describe("when there is one secret with the name (case-insensitive)", () -> {
        beforeEach(() -> {
          doReturn(1L).when(secretDataService).delete(secretName.toUpperCase());
          doReturn(new NamedValueSecret()).when(secretDataService).findMostRecent(secretName.toUpperCase());
          response = mockMvc.perform(delete("/api/v1/data?name=" + secretName.toUpperCase()));
        });

        it("should return a 200 status", () -> {
          response.andExpect(status().isOk());
        });

        it("asks data service to remove it from storage", () -> {
          verify(secretDataService, times(1)).delete(secretName.toUpperCase());
        });

        it("persists an audit entry", () -> {
          ArgumentCaptor<AuditRecordBuilder> captor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
          verify(auditLogService).performWithAuditing(captor.capture(), any(Supplier.class));
          AuditRecordBuilder auditRecorder = captor.getValue();
          assertThat(auditRecorder.getOperationCode(), equalTo(CREDENTIAL_DELETE));
          assertThat(auditRecorder.getCredentialName(), equalTo(secretName.toUpperCase()));
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

          response = mockMvc.perform(delete("/api/v1/data?name=" + secretName));
        });

        it("should succeed", () -> {
          response.andExpect(status().isOk());
        });

        it("should remove them all from the database", () -> {
          verify(secretDataService, times(1)).delete(secretName);
        });

        it("persists a single audit entry", () -> {
          ArgumentCaptor<AuditRecordBuilder> captor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
          verify(auditLogService, times(1)).performWithAuditing(captor.capture(), any(Supplier.class));
          AuditRecordBuilder auditRecorder = captor.getValue();
          assertThat(auditRecorder.getOperationCode(), equalTo(CREDENTIAL_DELETE));
          assertThat(auditRecorder.getCredentialName(), equalTo(secretName));
        });
      });

      describe("name can come as a request parameter", () -> {
        beforeEach(() -> {
          NamedValueSecret value1 = new NamedValueSecret(secretName);
          value1.setEncryptedValue("value1".getBytes());
          NamedValueSecret value2 = new NamedValueSecret(secretName);
          value2.setEncryptedValue("value2".getBytes());
          doReturn(2L).when(secretDataService).delete(secretName.toUpperCase());
          doReturn(new NamedValueSecret()).when(secretDataService).findMostRecent(secretName.toUpperCase());
        });

        it("can delete when the name is a query param", () -> {
          mockMvc.perform(delete("/api/v1/data?name=" + secretName.toUpperCase()))
            .andExpect(status().isOk());

          verify(secretDataService, times(1)).delete(secretName.toUpperCase());
        });

        it("handles missing name parameter", () -> {
          mockMvc.perform(delete("/api/v1/data"))
            .andExpect(status().isBadRequest());
        });

        it("handles empty name", () -> {
          mockMvc.perform(delete("/api/v1/data?name="))
              .andExpect(status().isBadRequest());
        });
      });
    });
  }

  private void resetAuditLogMock() throws Exception {
    Mockito.reset(auditLogService);
    doAnswer(invocation -> {
      final Supplier action = invocation.getArgumentAt(1, Supplier.class);
      return action.get();
    }).when(auditLogService).performWithAuditing(isA(AuditRecordBuilder.class), isA(Supplier.class));
  }
}
