package org.cloudfoundry.credhub.controller.v1;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.data.EventAuditRecordDataService;
import org.cloudfoundry.credhub.data.PermissionDataService;
import org.cloudfoundry.credhub.data.RequestAuditRecordDataService;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.domain.ValueCredentialVersion;
import org.cloudfoundry.credhub.entity.EventAuditRecord;
import org.cloudfoundry.credhub.entity.RequestAuditRecord;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_DELETE;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialsControllerAuditLogTest {

  @Autowired
  private WebApplicationContext applicationContext;

  @SpyBean
  private EventAuditRecordDataService eventAuditRecordDataService;

  @SpyBean
  private RequestAuditRecordDataService requestAuditRecordDataService;

  @MockBean
  private CredentialVersionDataService credentialVersionDataService;

  @MockBean
  private PermissionDataService permissionDataService;

  @SpyBean
  private Encryptor encryptor;

  private MockMvc mockMvc;

  @Before
  public void beforeEach() {
    mockMvc = MockMvcBuilders.webAppContextSetup(applicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void gettingACredential_byName_makesACredentialAccessLogEntry() throws Exception {
    doReturn(Arrays.asList(new PasswordCredentialVersion("/foo").setEncryptor(encryptor)))
        .when(credentialVersionDataService).findAllByName(eq("foo"));

    mockMvc.perform(get(CredentialsController.API_V1_DATA + "?name=foo")
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .header("X-Forwarded-For", "1.1.1.1,2.2.2.2"));

    ArgumentCaptor<List> recordCaptor = ArgumentCaptor
        .forClass(List.class);
    verify(eventAuditRecordDataService, times(1)).save(recordCaptor.capture());

    EventAuditRecord auditRecord = (EventAuditRecord) recordCaptor.getValue().get(0);

    assertThat(auditRecord.getCredentialName(), equalTo("/foo"));
    assertThat(auditRecord.getOperation(), equalTo(CREDENTIAL_ACCESS.toString()));
  }

  @Test
  public void gettingACredential_byId_makesACredentialAccessAuditLogEntry() throws Exception {
    doReturn(new PasswordCredentialVersion("/foo").setEncryptor(encryptor))
        .when(credentialVersionDataService).findByUuid(eq("foo-id"));

    mockMvc.perform(get(CredentialsController.API_V1_DATA + "/foo-id")
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .header("X-Forwarded-For", "1.1.1.1,2.2.2.2"));

    ArgumentCaptor<List> recordCaptor = ArgumentCaptor
        .forClass(List.class);
    verify(eventAuditRecordDataService, times(1)).save(recordCaptor.capture());

    EventAuditRecord auditRecord = (EventAuditRecord) recordCaptor.getValue().get(0);

    assertThat(auditRecord.getCredentialName(), equalTo("/foo"));
    assertThat(auditRecord.getOperation(), equalTo(CREDENTIAL_ACCESS.toString()));
  }

  @Test
  public void settingACredential_makesACredentialUpdateLogEntry() throws Exception {
    when(credentialVersionDataService.save(any(CredentialVersion.class))).thenAnswer(invocation -> {
      ValueCredentialVersion valueCredential = invocation.getArgumentAt(0, ValueCredentialVersion.class);
      valueCredential.setEncryptor(encryptor);
      valueCredential.setUuid(UUID.randomUUID());
      return valueCredential;
    });

    MockHttpServletRequestBuilder set = MockMvcRequestBuilders.put(CredentialsController.API_V1_DATA)
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
        .content("{\"type\":\"value\",\"name\":\"foo\",\"value\":\"credential\"}")
        .with(request -> {
          request.setRemoteAddr("12346");
          return request;
        });

    mockMvc.perform(set)
        .andExpect(status().isOk());

    ArgumentCaptor<List> recordCaptor = ArgumentCaptor
        .forClass(List.class);
    verify(eventAuditRecordDataService, times(1)).save(recordCaptor.capture());

    EventAuditRecord auditRecord = (EventAuditRecord) recordCaptor.getValue().get(0);

    assertThat(auditRecord.getCredentialName(), equalTo("/foo"));
    assertThat(auditRecord.getOperation(), equalTo(CREDENTIAL_UPDATE.toString()));
  }

  @Test
  public void deletingACredential_makesACredentialDeleteLogEntry() throws Exception {
    MockHttpServletRequestBuilder deleteRequest = delete(CredentialsController.API_V1_DATA + "?name=foo")
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
        .with(request -> {
          request.setRemoteAddr("12345");
          return request;
        });

    mockMvc.perform(deleteRequest)
        .andExpect(status().is4xxClientError());

    ArgumentCaptor<List> recordCaptor = ArgumentCaptor
        .forClass(List.class);
    verify(eventAuditRecordDataService, times(1)).save(recordCaptor.capture());

    EventAuditRecord auditRecord = (EventAuditRecord) recordCaptor.getValue().get(0);

    assertThat(auditRecord.getCredentialName(), equalTo("/foo"));
    assertThat(auditRecord.getOperation(), equalTo(CREDENTIAL_DELETE.toString()));
  }

  @Test
  public void whenARequestHasMultipleXForwardedForHeaders_logsAllXForwardedForValues() throws Exception {
    when(credentialVersionDataService.save(any(CredentialVersion.class))).thenAnswer(invocation -> {
      ValueCredentialVersion valueCredential = invocation.getArgumentAt(0, ValueCredentialVersion.class);
      valueCredential.setUuid(UUID.randomUUID());
      return valueCredential;
    });

    MockHttpServletRequestBuilder putRequest = MockMvcRequestBuilders.put(CredentialsController.API_V1_DATA)
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
        .header("X-Forwarded-For", "3.3.3.3")
        .content("{\"type\":\"value\",\"name\":\"foo\",\"value\":\"password\"}")
        .with(request -> {
          request.setRemoteAddr("12346");
          return request;
        });

    mockMvc.perform(putRequest)
        .andExpect(status().isOk());

    ArgumentCaptor<RequestAuditRecord> recordCaptor = ArgumentCaptor
        .forClass(RequestAuditRecord.class);

    verify(requestAuditRecordDataService, times(1)).save(recordCaptor.capture());

    RequestAuditRecord auditRecord = recordCaptor.getValue();

    assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2,3.3.3.3"));
  }
}
