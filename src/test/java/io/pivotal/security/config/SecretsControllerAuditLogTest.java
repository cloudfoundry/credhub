package io.pivotal.security.config;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.data.OperationAuditRecordDataService;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.service.DatabaseAuditLogService;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.controller.v1.secret.SecretsController.API_V1_DATA;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_DELETE;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.helper.SpectrumHelper.cleanUpAfterTests;
import static io.pivotal.security.helper.SpectrumHelper.cleanUpBeforeTests;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import javax.servlet.Filter;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(CredentialManagerApp.class)
@WebAppConfiguration
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test", "SecretsControllerAuditLogTest", "NoExpirationSymmetricKeySecurityConfiguration"})
public class SecretsControllerAuditLogTest {

  @Autowired
  WebApplicationContext applicationContext;

  @Autowired
  @InjectMocks
  DatabaseAuditLogService auditLogService;

  @Mock
  OperationAuditRecordDataService operationAuditRecordDataService;

  @Autowired
  Filter springSecurityFilterChain;

  private MockMvc mockMvc;

  {
    wireAndUnwire(this);
    cleanUpBeforeTests(this);
    cleanUpAfterTests(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(applicationContext)
          .addFilter(springSecurityFilterChain)
          .build();
    });

    describe("when a request to set credential is served", () -> {

      beforeEach(() -> {
        MockHttpServletRequestBuilder set = put(API_V1_DATA)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .content("{\"type\":\"value\",\"name\":\"foo\",\"value\":\"password\"}")
            .with(request -> {
              request.setRemoteAddr("12346");
              return request;
            });

        mockMvc.perform(set)
            .andExpect(status().isOk());
      });

      it("logs an audit record for credential update operation", () -> {
        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);

        verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

        OperationAuditRecord auditRecord = recordCaptor.getValue();

        assertThat(auditRecord.getPath(), equalTo(API_V1_DATA));
        assertThat(auditRecord.getCredentialName(), equalTo("foo"));
        assertThat(auditRecord.getOperation(), equalTo(CREDENTIAL_UPDATE.toString()));
        assertThat(auditRecord.getRequesterIp(), equalTo("12346"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
      });
    });

    describe("when a request to generate a credential is served", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder post = post(API_V1_DATA)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .content("{\"type\":\"password\",\"name\":\"foo\"}")
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .with(request -> {
              request.setRemoteAddr("12345");
              return request;
            });

        mockMvc.perform(post)
            .andExpect(status().isOk());
      });

      it("logs an audit record for credential_update operation", () -> {
        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);

        verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

        OperationAuditRecord auditRecord = recordCaptor.getValue();

        assertThat(auditRecord.getPath(), equalTo(API_V1_DATA));
        assertThat(auditRecord.getCredentialName(), equalTo("foo"));
        assertThat(auditRecord.getOperation(), equalTo(CREDENTIAL_UPDATE.toString()));
        assertThat(auditRecord.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
      });
    });

    describe("when a request to delete a credential is served", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder delete = delete(API_V1_DATA + "?name=foo")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .with(request -> {
              request.setRemoteAddr("12345");
              return request;
            });

        mockMvc.perform(delete)
            .andExpect(status().is4xxClientError());
      });

      it("logs an audit record for credential_delete operation", () -> {
        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);

        verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

        OperationAuditRecord auditRecord = recordCaptor.getValue();

        assertThat(auditRecord.getPath(), equalTo(API_V1_DATA));
        assertThat(auditRecord.getOperation(), equalTo(CREDENTIAL_DELETE.toString()));
        assertThat(auditRecord.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
      });
    });

    describe("when a request to retrieve a credential is served", () -> {
      beforeEach(() -> {
        doUnsuccessfulFetch("foo");
      });

      it("logs an audit record for credential_access operation", () -> {
        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);

        verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

        OperationAuditRecord auditRecord = recordCaptor.getValue();

        assertThat(auditRecord.getPath(), equalTo(API_V1_DATA));
        assertThat(auditRecord.getOperation(), equalTo(CREDENTIAL_ACCESS.toString()));
        assertThat(auditRecord.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
      });
    });

    describe("when a request has multiple X-Forwarded-For headers set", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder set = put(API_V1_DATA)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .header("X-Forwarded-For", "3.3.3.3")
            .content("{\"type\":\"value\",\"name\":\"foo\",\"value\":\"password\"}")
            .with(request -> {
              request.setRemoteAddr("12346");
              return request;
            });

        mockMvc.perform(set)
            .andExpect(status().isOk());
      });

      it("logs all X-Forwarded-For values", () -> {
        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);

        verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

        OperationAuditRecord auditRecord = recordCaptor.getValue();

        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2,3.3.3.3"));
      });
    });
  }

  private void doUnsuccessfulFetch(String credentialName) throws Exception {
    MockHttpServletRequestBuilder get = get(API_V1_DATA + "?name=" + credentialName)
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
        .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
        .with(request -> {
          request.setRemoteAddr("12345");
          return request;
        });

    mockMvc.perform(get)
        .andExpect(status().is4xxClientError());
  }
}
