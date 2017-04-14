package io.pivotal.security.integration;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
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

  private MockMvc mockMvc;

  @Before
  public void setup() {
    mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void normally_logs_event_and_request() throws Exception {
    String secretName = "/TEST/SECRET";
    String secretType = "password";

    mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "\"name\":\"" + secretName + "\"," +
            "\"type\":\"" + secretType + "\"" +
            "}"
        )
    ).andExpect(status().isOk());

    assertThat(requestAuditRecordRepository.count(), equalTo(1L));
    assertThat(eventAuditRecordRepository.count(), equalTo(1L));

    RequestAuditRecord requestAuditRecord = requestAuditRecordRepository.findAll().get(0);
    assertThat(requestAuditRecord.getAuthMethod(), equalTo("uaa"));
    // more assertions

    EventAuditRecord eventAuditRecord = eventAuditRecordRepository.findAll().get(0);
    assertThat(eventAuditRecord.getCredentialName(), equalTo("/TEST/SECRET"));
    // more assertions
  }
}
