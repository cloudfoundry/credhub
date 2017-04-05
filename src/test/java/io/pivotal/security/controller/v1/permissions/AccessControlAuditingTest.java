package io.pivotal.security.controller.v1.permissions;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.OperationAuditRecordDataService;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.util.DatabaseProfileResolver;
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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static io.pivotal.security.entity.AuditingOperationCode.ACL_ACCESS;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles(
  profiles = {"unit-test", "UseRealAuditLogService"},
  resolver = DatabaseProfileResolver.class
)
@SpringBootTest(classes = CredentialManagerApp.class)
public class AccessControlAuditingTest {

  @Autowired
  private WebApplicationContext applicationContext;

  @SpyBean
  private OperationAuditRecordDataService operationAuditRecordDataService;

  private MockMvc mockMvc;

  @Before
  public void setUp() throws Exception {
    mockMvc = MockMvcBuilders.webAppContextSetup(applicationContext)
      .apply(springSecurity())
      .build();

    MockHttpServletRequestBuilder put = put("/api/v1/data")
      .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"name\": \"/cred1\","
        + "  \"type\": \"password\","
        + "  \"value\": \"testpassword\""
        + "}");

    this.mockMvc.perform(put)
      .andExpect(status().isOk());
    reset(operationAuditRecordDataService);
  }

  @Test
  public void whenGettingAnAcl_itLogsTheRetrieval() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/acls?credential_name=/cred1")
      .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    this.mockMvc.perform(get)
      .andExpect(status().isOk());

    ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor
      .forClass(OperationAuditRecord.class);
    verify(operationAuditRecordDataService).save(recordCaptor.capture());

    OperationAuditRecord auditRecord = recordCaptor.getValue();

    assertThat(auditRecord.getCredentialName(), equalTo("/cred1"));
    assertThat(auditRecord.getOperation(), equalTo(ACL_ACCESS.toString()));
  }
}