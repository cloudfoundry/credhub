package org.cloudfoundry.credhub.integration;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.data.EventAuditRecordDataService;
import org.cloudfoundry.credhub.data.RequestAuditRecordDataService;
import org.cloudfoundry.credhub.entity.EventAuditRecord;
import org.cloudfoundry.credhub.entity.RequestAuditRecord;
import org.cloudfoundry.credhub.helper.AuditingHelper;
import org.cloudfoundry.credhub.repository.CredentialVersionRepository;
import org.cloudfoundry.credhub.repository.EventAuditRecordRepository;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.data.domain.Sort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;

import static java.util.Collections.emptyList;
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

@RunWith(SpringRunner.class)
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
  private CredentialVersionRepository credentialVersionRepository;
  @SpyBean
  private Logger logger;
  @SpyBean
  private EventAuditRecordDataService eventAuditRecordDataService;
  @SpyBean
  private RequestAuditRecordDataService requestAuditRecordDataService;

  private MockMvc mockMvc;
  private AuditingHelper auditingHelper;

  private Sort sortByDate = new Sort(Sort.Direction.DESC, "now");
  @Before
  public void setup() {
    mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
  }

  @Test
  public void does_not_audit_info_endpoint() throws Exception {
    long initialRequestAuditCount = requestAuditRecordRepository.count();
    long initialEventAuditCount = eventAuditRecordRepository.count();

    mockMvc.perform(get("/info")
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
    ).andExpect(status().isOk());


    assertThat(requestAuditRecordRepository.count(), equalTo(initialRequestAuditCount));
    assertThat(eventAuditRecordRepository.count(), equalTo(initialEventAuditCount));
  }

  @Test
  public void does_not_audit_health_endpoint() throws Exception {
    long initialRequestAuditCount = requestAuditRecordRepository.count();
    long initialEventAuditCount = eventAuditRecordRepository.count();

    mockMvc.perform(get("/health")
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
    ).andExpect(status().isOk());

    assertThat(requestAuditRecordRepository.count(), equalTo(initialRequestAuditCount));
    assertThat(eventAuditRecordRepository.count(), equalTo(initialEventAuditCount));
  }

  @Test
  public void normally_logs_event_and_request() throws Exception {
    String credentialName = "/TEST/SECRET";
    String credentialType = "password";
    long initialRequestAuditCount = requestAuditRecordRepository.count();
    long initialEventAuditCount = eventAuditRecordRepository.count();

    mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\":\"" + credentialName + "\"," +
            "\"type\":\"" + credentialType + "\"" +
            "}"
        )
    ).andExpect(status().isOk());

    assertThat(requestAuditRecordRepository.count(), equalTo(1L + initialRequestAuditCount));
    assertThat(eventAuditRecordRepository.count(), equalTo(6L + initialEventAuditCount));

    RequestAuditRecord requestAuditRecord = requestAuditRecordRepository.findAll(sortByDate).get(0);
    assertThat(requestAuditRecord.getAuthMethod(), equalTo("uaa"));
    assertThat(requestAuditRecord.getPath(), equalTo("/api/v1/data"));

    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
    verify(logger, times(1)).info(captor.capture());
    assertThat(captor.getValue(), containsString("cs4=200"));

    EventAuditRecord eventAuditRecord = eventAuditRecordRepository.findAll(sortByDate).get(0);
    assertThat(eventAuditRecord.getCredentialName(), equalTo("/TEST/SECRET"));
    assertThat(eventAuditRecord.getActor(), equalTo(AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID));
  }

  @Test
  public void when_event_fails_it_logs_correct_success_flag_and_status_code() throws Exception {
    long initialRequestAuditCount = requestAuditRecordRepository.count();
    long initialEventAuditCount = eventAuditRecordRepository.count();
    String credentialName = "/TEST/SECRET";

    mockMvc.perform(get("/api/v1/data?name=" + credentialName)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
    ).andExpect(status().isNotFound());

    assertThat(requestAuditRecordRepository.count(), equalTo(initialRequestAuditCount +1L));
    assertThat(eventAuditRecordRepository.count(), equalTo(initialEventAuditCount+ 1));

    RequestAuditRecord requestAuditRecord = requestAuditRecordRepository.findAll(sortByDate).get(0);
    assertThat(requestAuditRecord.getStatusCode(), equalTo(404));

    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
    verify(logger, times(1)).info(captor.capture());
    assertThat(captor.getValue(), containsString("cs4=404"));

    EventAuditRecord eventAuditRecord = eventAuditRecordRepository.findAll(sortByDate).get(0);
    assertThat(eventAuditRecord.isSuccess(), equalTo(false));
    assertThat(eventAuditRecord.getActor(), equalTo(AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID));
  }

  @Test
  public void when_event_audit_record_save_fails_it_rolls_back_event() throws Exception {
    long initialRequestAuditCount = requestAuditRecordRepository.count();
    long initialEventAuditCount = eventAuditRecordRepository.count();
    long initialCredentialCount = credentialVersionRepository.count();
    doThrow(new RuntimeException("test"))
        .when(eventAuditRecordDataService).save(any(List.class));

    assertThat(eventAuditRecordRepository.count(), equalTo(initialEventAuditCount));

    mockMvc.perform(get("/api/v1/data?name=foo")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
    ).andExpect(status().isInternalServerError());

    assertThat(credentialVersionRepository.count(), equalTo(initialCredentialCount));
    assertThat(eventAuditRecordRepository.count(), equalTo(initialEventAuditCount+0L));

    assertThat(requestAuditRecordRepository.count(), equalTo(initialRequestAuditCount+1L));
  }

  @Test
  public void when_event_audit_record_save_fails_it_saves_request_audit_record() throws Exception {
    long initialRequestAuditCount = requestAuditRecordRepository.count();
    long initialEventAuditCount = eventAuditRecordRepository.count();
    String credentialName = "/TEST/SECRET";
    String credentialType = "password";

    doThrow(new RuntimeException("test exception"))
        .when(eventAuditRecordDataService).save(any(List.class));

    mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\":\"" + credentialName + "\"," +
            "\"type\":\"" + credentialType + "\"" +
            "}"
        )
    ).andExpect(status().isInternalServerError());

    assertThat(requestAuditRecordRepository.count(), equalTo(initialRequestAuditCount + 1));

    RequestAuditRecord requestAuditRecord = requestAuditRecordRepository.findAll(sortByDate).get(0);
    assertThat(requestAuditRecord.getStatusCode(), equalTo(500));

    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
    verify(logger, times(1)).info(captor.capture());
    assertThat(captor.getValue(), containsString("cs4=500"));
  }

  @Test
  public void when_request_audit_record_save_fails_it_still_logs_to_CEF_logs() throws Exception {
    long initialRequestAuditCount = requestAuditRecordRepository.count();
    long initialEventAuditCount = eventAuditRecordRepository.count();
    doThrow(new RuntimeException("test"))
        .when(requestAuditRecordDataService).save(any(RequestAuditRecord.class));

    String credentialName = "/TEST/SECRET";

    mockMvc.perform(get("/api/v1/data?name=" + credentialName)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
    ).andExpect(status().isNotFound());

    assertThat("it does not log a request", requestAuditRecordRepository.count(), equalTo(initialRequestAuditCount));
    assertThat("it does log the event", eventAuditRecordRepository.count(), equalTo(initialEventAuditCount + 1L));

    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
    verify(logger, times(1)).info(captor.capture());
    assertThat("failure is in CEF log", captor.getValue(), containsString("cs4=404"));
  }

  @Test
  public void given_request_it_logs_to_CEF_logs_with_correct_user() throws Exception {
    mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .content("{\"name\" : \"/cred1\", \"type\": \"password\"}")
        .contentType(APPLICATION_JSON)
    ).andExpect(status().isOk());

    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
    verify(logger).info(captor.capture());

    String expectedOutputPart1 = "CEF:0|cloud_foundry|credhub|";
    String expectedOutputPart2 = "|POST /api/v1/data|POST /api/v1/data|0|";
    String expectedOutputPart3 = "suser=credhub_cli suid=uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d cs1Label=userAuthenticationMechanism cs1=oauth-access-token request=/api/v1/data requestMethod=POST cs3Label=result cs3=success cs4Label=httpStatusCode cs4=200 src=127.0.0.1 dst=localhost";
    assertThat("it logs correct entry", captor.getValue(), containsString(expectedOutputPart1));
    assertThat("it logs correct entry", captor.getValue(), containsString(expectedOutputPart2));
    assertThat("it logs correct entry", captor.getValue(), containsString(expectedOutputPart3));
  }

  @Test
  public void correctly_logs_exceptions_not_handled_specifically() throws Exception {
    MockHttpServletRequestBuilder request = post("/api/v1/data")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);
    mockMvc.perform(request)
        .andExpect(status().isInternalServerError());

    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
    verify(logger).info(captor.capture());

    assertThat(captor.getValue(), containsString("cs4Label=httpStatusCode cs4=500"));

    auditingHelper.verifyAuditing(
        AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID,
        "/api/v1/data",
        500,
        emptyList()
    );
  }
}
