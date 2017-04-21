package io.pivotal.security.integration;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.EventAuditRecordDataService;
import io.pivotal.security.data.RequestAuditRecordDataService;
import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.repository.CredentialRepository;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;

import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class AuditTest {
  @Autowired
  private WebApplicationContext webApplicationContext;
  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;
  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;
  @Autowired
  private CredentialRepository credentialRepository;
  @SpyBean
  private Logger logger;
  @SpyBean
  private EventAuditRecordDataService eventAuditRecordDataService;
  @SpyBean
  private RequestAuditRecordDataService requestAuditRecordDataService;

  private MockMvc mockMvc;

  @Before
  public void setup() {
    mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void does_not_audit_info_endpoint() throws Exception {
    mockMvc.perform(get("/info")
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
    ).andExpect(status().isOk());

    assertThat(requestAuditRecordRepository.count(), equalTo(0L));
    assertThat(eventAuditRecordRepository.count(), equalTo(0L));
  }

  @Test
  public void does_not_audit_health_endpoint() throws Exception {
    mockMvc.perform(get("/info")
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
    ).andExpect(status().isOk());

    assertThat(requestAuditRecordRepository.count(), equalTo(0L));
    assertThat(eventAuditRecordRepository.count(), equalTo(0L));
  }

  @Test
  public void normally_logs_event_and_request() throws Exception {
    String credentialName = "/TEST/SECRET";
    String credentialType = "password";

    mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\":\"" + credentialName + "\"," +
            "\"type\":\"" + credentialType + "\"" +
            "}"
        )
    ).andExpect(status().isOk());

    assertThat(requestAuditRecordRepository.count(), equalTo(1L));
    assertThat(eventAuditRecordRepository.count(), equalTo(1L));

    RequestAuditRecord requestAuditRecord = requestAuditRecordRepository.findAll().get(0);
    assertThat(requestAuditRecord.getAuthMethod(), equalTo("uaa"));
    assertThat(requestAuditRecord.getPath(), equalTo("/api/v1/data"));

    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
    verify(logger, times(1)).info(captor.capture());
    assertThat(captor.getValue(), containsString("cs4=200"));

    EventAuditRecord eventAuditRecord = eventAuditRecordRepository.findAll().get(0);
    assertThat(eventAuditRecord.getCredentialName(), equalTo("/TEST/SECRET"));
    assertThat(eventAuditRecord.getActor(), equalTo("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d"));
  }

  @Test
  public void when_event_fails_it_logs_correct_success_flag_and_status_code() throws Exception {
    String credentialName = "/TEST/SECRET";

    mockMvc.perform(get("/api/v1/data?name=" + credentialName)
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
    ).andExpect(status().isNotFound());

    assertThat(requestAuditRecordRepository.count(), equalTo(1L));
    assertThat(eventAuditRecordRepository.count(), equalTo(1L));

    RequestAuditRecord requestAuditRecord = requestAuditRecordRepository.findAll().get(0);
    assertThat(requestAuditRecord.getStatusCode(), equalTo(404));

    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
    verify(logger, times(1)).info(captor.capture());
    assertThat(captor.getValue(), containsString("cs4=404"));

    EventAuditRecord eventAuditRecord = eventAuditRecordRepository.findAll().get(0);
    assertThat(eventAuditRecord.isSuccess(), equalTo(false));
    assertThat(eventAuditRecord.getActor(), equalTo("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d"));
  }

  @Test
  public void when_event_audit_record_save_fails_it_rolls_back_event() throws Exception {
    doThrow(new RuntimeException("test"))
        .when(eventAuditRecordDataService).save(any(List.class));

    assertThat(eventAuditRecordRepository.count(), equalTo(0L));

    mockMvc.perform(get("/api/v1/data?name=foo")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
    ).andExpect(status().isInternalServerError());

    assertThat(credentialRepository.count(), equalTo(0L));
    assertThat(eventAuditRecordRepository.count(), equalTo(0L));

    assertThat(requestAuditRecordRepository.count(), equalTo(1L));
  }

  @Test
  public void when_event_audit_record_save_fails_it_saves_request_audit_record() throws Exception {
    String credentialName = "/TEST/SECRET";
    String credentialType = "password";

    doThrow(new RuntimeException("test exception"))
        .when(eventAuditRecordDataService).save(any(List.class));

    mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\":\"" + credentialName + "\"," +
            "\"type\":\"" + credentialType + "\"" +
            "}"
        )
    ).andExpect(status().isInternalServerError());

    assertThat(requestAuditRecordRepository.count(), equalTo(1L));

    RequestAuditRecord requestAuditRecord = requestAuditRecordRepository.findAll().get(0);
    assertThat(requestAuditRecord.getStatusCode(), equalTo(500));

    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
    verify(logger, times(1)).info(captor.capture());
    assertThat(captor.getValue(), containsString("cs4=500"));
  }

  @Test
  public void when_request_audit_record_save_fails_it_still_logs_to_CEF_logs() throws Exception {
    doThrow(new RuntimeException("test"))
        .when(requestAuditRecordDataService).save(any(RequestAuditRecord.class));

    String credentialName = "/TEST/SECRET";

    mockMvc.perform(get("/api/v1/data?name=" + credentialName)
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
    ).andExpect(status().isNotFound());

    assertThat(requestAuditRecordRepository.count(), equalTo(0L));
    assertThat(eventAuditRecordRepository.count(), equalTo(1L));

    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
    verify(logger, times(1)).info(captor.capture());
    assertThat(captor.getValue(), containsString("cs4=404"));
  }
}
