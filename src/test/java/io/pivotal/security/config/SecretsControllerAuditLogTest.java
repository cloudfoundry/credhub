package io.pivotal.security.config;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.EventAuditRecordDataService;
import io.pivotal.security.data.RequestAuditRecordDataService;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_DELETE;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.controller.v1.secret.SecretsController.API_V1_DATA;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerAuditLogTest {

  @Autowired
  WebApplicationContext applicationContext;

  @SpyBean
  EventAuditRecordDataService eventAuditRecordDataService;

  @SpyBean
  RequestAuditRecordDataService requestAuditRecordDataService;

  @MockBean
  SecretDataService secretDataService;

  @SpyBean
  Encryptor encryptor;

  private MockMvc mockMvc;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(applicationContext)
          .apply(springSecurity())
          .build();
    });

    describe("when getting a credential", () -> {
      describe("by name", () -> {
        it("makes a credential_access audit log entry", () -> {
          doReturn(Arrays.asList(new NamedPasswordSecret("/foo").setEncryptor(encryptor)))
              .when(secretDataService).findAllByName(eq("foo"));

          mockMvc.perform(get(API_V1_DATA + "?name=foo")
              .accept(MediaType.APPLICATION_JSON)
              .contentType(MediaType.APPLICATION_JSON)
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .header("X-Forwarded-For", "1.1.1.1,2.2.2.2"));

          ArgumentCaptor<List> recordCaptor = ArgumentCaptor
              .forClass(List.class);
          verify(eventAuditRecordDataService, times(1)).save(recordCaptor.capture());

          EventAuditRecord auditRecord = (EventAuditRecord) recordCaptor.getValue().get(0);

          assertThat(auditRecord.getCredentialName(), equalTo("/foo"));
          assertThat(auditRecord.getOperation(), equalTo(CREDENTIAL_ACCESS.toString()));
        });
      });

      describe("by id", () -> {
        it("makes a credential_access audit log entry", () -> {
          doReturn(new NamedPasswordSecret("/foo").setEncryptor(encryptor))
              .when(secretDataService).findByUuid(eq("foo-id"));

          mockMvc.perform(get(API_V1_DATA + "/foo-id")
              .accept(MediaType.APPLICATION_JSON)
              .contentType(MediaType.APPLICATION_JSON)
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .header("X-Forwarded-For", "1.1.1.1,2.2.2.2"));

          ArgumentCaptor<List> recordCaptor = ArgumentCaptor
              .forClass(List.class);
          verify(eventAuditRecordDataService, times(1)).save(recordCaptor.capture());

          EventAuditRecord auditRecord = (EventAuditRecord) recordCaptor.getValue().get(0);

          assertThat(auditRecord.getCredentialName(), equalTo("/foo"));
          assertThat(auditRecord.getOperation(), equalTo(CREDENTIAL_ACCESS.toString()));
        });
      });
    });

    describe("when a request to set credential is served", () -> {
      beforeEach(() -> {
        when(secretDataService.save(any(NamedSecret.class))).thenAnswer(invocation -> {
          NamedValueSecret namedValueSecret = invocation.getArgumentAt(0, NamedValueSecret.class);
          namedValueSecret.setEncryptor(encryptor);
          namedValueSecret.setUuid(UUID.randomUUID());
          return namedValueSecret;
        });

        MockHttpServletRequestBuilder set = put(API_V1_DATA)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .content("{\"type\":\"value\",\"name\":\"foo\",\"value\":\"secret\"}")
            .with(request -> {
              request.setRemoteAddr("12346");
              return request;
            });

        mockMvc.perform(set)
            .andExpect(status().isOk());
      });

      it("logs an audit record for credential update operation", () -> {
        ArgumentCaptor<List> recordCaptor = ArgumentCaptor
            .forClass(List.class);
        verify(eventAuditRecordDataService, times(1)).save(recordCaptor.capture());

        EventAuditRecord auditRecord = (EventAuditRecord) recordCaptor.getValue().get(0);

        assertThat(auditRecord.getCredentialName(), equalTo("/foo"));
        assertThat(auditRecord.getOperation(), equalTo(CREDENTIAL_UPDATE.toString()));
      });
    });

    describe("when a request to generate a credential is served", () -> {
      beforeEach(() -> {
        when(secretDataService.save(any(NamedSecret.class))).thenAnswer(invocation -> {
          NamedPasswordSecret namedPasswordSecret = invocation
              .getArgumentAt(0, NamedPasswordSecret.class);
          namedPasswordSecret.setUuid(UUID.randomUUID());
          return namedPasswordSecret;
        });

        MockHttpServletRequestBuilder post = post(API_V1_DATA)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
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
        ArgumentCaptor<List> recordCaptor = ArgumentCaptor
            .forClass(List.class);
        verify(eventAuditRecordDataService, times(1)).save(recordCaptor.capture());

        EventAuditRecord auditRecord = (EventAuditRecord) recordCaptor.getValue().get(0);

        assertThat(auditRecord.getCredentialName(), equalTo("/foo"));
        assertThat(auditRecord.getOperation(), equalTo(CREDENTIAL_UPDATE.toString()));
      });
    });

    describe("when a request to delete a credential is served", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder delete = delete(API_V1_DATA + "?name=foo")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .with(request -> {
              request.setRemoteAddr("12345");
              return request;
            });

        mockMvc.perform(delete)
            .andExpect(status().is4xxClientError());
      });

      it("logs an audit record for credential_delete operation", () -> {
        ArgumentCaptor<List> recordCaptor = ArgumentCaptor
            .forClass(List.class);
        verify(eventAuditRecordDataService, times(1)).save(recordCaptor.capture());

        EventAuditRecord auditRecord = (EventAuditRecord) recordCaptor.getValue().get(0);

        assertThat(auditRecord.getCredentialName(), equalTo("foo"));
        assertThat(auditRecord.getOperation(), equalTo(CREDENTIAL_DELETE.toString()));
      });
    });

    describe("when a request to retrieve a credential is served", () -> {
      beforeEach(() -> {
        doUnsuccessfulFetch("foo");
      });

      it("logs an audit record for credential_access operation", () -> {
        ArgumentCaptor<List> recordCaptor = ArgumentCaptor
            .forClass(List.class);
        verify(eventAuditRecordDataService, times(1)).save(recordCaptor.capture());

        EventAuditRecord auditRecord = (EventAuditRecord) recordCaptor.getValue().get(0);

        assertThat(auditRecord.getOperation(), equalTo(CREDENTIAL_ACCESS.toString()));
        assertThat(auditRecord.getCredentialName(), equalTo(null));
      });
    });

    describe("when a request has multiple X-Forwarded-For headers set", () -> {
      beforeEach(() -> {
        when(secretDataService.save(any(NamedSecret.class))).thenAnswer(invocation -> {
          NamedValueSecret namedValueSecret = invocation.getArgumentAt(0, NamedValueSecret.class);
          namedValueSecret.setUuid(UUID.randomUUID());
          return namedValueSecret;
        });

        MockHttpServletRequestBuilder set = put(API_V1_DATA)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
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
        ArgumentCaptor<RequestAuditRecord> recordCaptor = ArgumentCaptor
            .forClass(RequestAuditRecord.class);

        verify(requestAuditRecordDataService, times(1)).save(recordCaptor.capture());

        RequestAuditRecord auditRecord = recordCaptor.getValue();

        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2,3.3.3.3"));
      });
    });
  }

  private void doUnsuccessfulFetch(String credentialName) throws Exception {
    MockHttpServletRequestBuilder get = get(API_V1_DATA + "?name=" + credentialName)
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
        .with(request -> {
          request.setRemoteAddr("12345");
          return request;
        });

    mockMvc.perform(get)
        .andExpect(status().is4xxClientError());
  }
}
