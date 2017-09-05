package io.pivotal.security.controller.v1;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.audit.EventAuditLogService;
import io.pivotal.security.audit.RequestUuid;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.service.RegenerateService;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class RegenerateControllerTest {
  @Autowired
  private WebApplicationContext webApplicationContext;

  @MockBean
  private RegenerateService regenerateService;

  @SpyBean
  private EventAuditLogService eventAuditLogService;

  private MockMvc mockMvc;

  @Before
  public void beforeEach() {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void POST_regeneratesThePassword_andPersistsAnAuditEntry() throws Exception {
    mockMvc.perform(makeValidPostRequest()).andDo(print()).andExpect(status().isOk());

    Mockito.verify(regenerateService).performRegenerate(eq("picard"), any(UserContext.class), any(PermissionEntry.class), any());
    Mockito.verify(eventAuditLogService).auditEvents(any(RequestUuid.class), org.mockito.Matchers.argThat(
        org.hamcrest.Matchers.hasProperty("userId", org.hamcrest.Matchers.equalTo("df0c1a26-2875-4bf5-baf9-716c6bb5ea6d"))
    ), any());
  }

  private MockHttpServletRequestBuilder makeValidPostRequest() {
    return post("/api/v1/regenerate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\n"
            + "  \"name\" : \"picard\"\n"
            + "}");
  }
}
