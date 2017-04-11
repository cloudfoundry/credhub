package io.pivotal.security.controller.v1.permissions;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.data.RequestAuditRecordDataService;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_ACCESS;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles(
  profiles = {"unit-test", "UseRealAuditLogService"},
  resolver = DatabaseProfileResolver.class
)
@SpringBootTest(classes = CredentialManagerApp.class)
public class AccessControlAuditingTest {

  public static final String CRED1 = "/cred1";
  public static final String TESTPASSWORD = "testpassword";
  @Autowired
  private WebApplicationContext applicationContext;

  @MockBean
  private RequestAuditRecordDataService requestAuditRecordDataService;

  @MockBean
  private AccessControlDataService accessControlDataService;

  @MockBean
  private PermissionService permissionService;

  private MockMvc mockMvc;

  @Before
  public void setUp() throws Exception {
    mockMvc = MockMvcBuilders.webAppContextSetup(applicationContext)
      .apply(springSecurity())
      .build();
    AccessControlEntry ace = new AccessControlEntry(
        "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
        Arrays.asList(AccessControlOperation.READ_ACL));
    when(accessControlDataService.getAccessControlList(eq(CRED1))).thenReturn(Arrays.asList(ace));
    reset(requestAuditRecordDataService);
  }

  @Test
  public void whenGettingAnAcl_itLogsTheRetrieval() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/acls?credential_name=" + CRED1)
      .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    this.mockMvc.perform(get)
      .andExpect(status().isOk());

    ArgumentCaptor<RequestAuditRecord> recordCaptor = ArgumentCaptor
      .forClass(RequestAuditRecord.class);
    verify(requestAuditRecordDataService).save(recordCaptor.capture());

    RequestAuditRecord auditRecord = recordCaptor.getValue();

    assertThat(auditRecord.getCredentialName(), equalTo(CRED1));
    assertThat(auditRecord.getOperation(), equalTo(ACL_ACCESS.toString()));
  }
}
