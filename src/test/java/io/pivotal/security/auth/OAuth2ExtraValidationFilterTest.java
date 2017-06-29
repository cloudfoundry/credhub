package io.pivotal.security.auth;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.helper.AuditingHelper;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static io.pivotal.security.util.AuthConstants.EMPTY_ISSUER_JWT;
import static io.pivotal.security.util.AuthConstants.INVALID_ISSUER_JWT;
import static io.pivotal.security.util.AuthConstants.NULL_ISSUER_JWT;
import static io.pivotal.security.util.AuthConstants.VALID_ISSUER_JWT;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class OAuth2ExtraValidationFilterTest {

  @Autowired
  private WebApplicationContext webApplicationContext;

  @SpyBean
  private OAuth2IssuerService oAuth2IssuerService;

  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;

  private MockMvc mockMvc;
  private AuditingHelper auditingHelper;
  private final static String ERROR_MESSAGE = "The request token identity zone does not match the UAA server authorized by CredHub. Please validate that your request token was issued by the UAA server authorized by CredHub and retry your request.";

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
    auditingHelper = new AuditingHelper(requestAuditRecordRepository, null);

    when(oAuth2IssuerService.getIssuer()).thenReturn("https://example.com:8443/uaa/oauth/token");
  }

  @Test
  public void whenGivenValidIssuer_returns200_andAuditsRequest() throws Exception {
    when(oAuth2IssuerService.getIssuer()).thenReturn("https://valid-uaa:8443/uaa/oauth/token");

    this.mockMvc.perform(post("/api/v1/data")
        .header("Authorization", "Bearer " + VALID_ISSUER_JWT)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{  " +
            "\"name\": \"/picard\", \n" +
            "  \"type\": \"password\" \n" +
            "}"))
        .andExpect(status().isOk());

    auditingHelper.verifyRequestAuditing("/api/v1/data", 200);
  }

  @Test
  public void whenGivenInvalidIssuer_returns401_andAuditsRequest() throws Exception {
    this.mockMvc.perform(post("/api/v1/data?name=/picard")
        .header("Authorization", "Bearer " + INVALID_ISSUER_JWT)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error_description").value(ERROR_MESSAGE));

    auditingHelper.verifyRequestAuditing("/api/v1/data", 401);
  }

  @Test
  public void whenGivenNullIssuer_returns401_andAuditsRequest() throws Exception {
    this.mockMvc.perform(post("/api/v1/data?name=/picard")
        .header("Authorization", "Bearer " + NULL_ISSUER_JWT)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error_description").value(ERROR_MESSAGE));

    auditingHelper.verifyRequestAuditing("/api/v1/data", 401);
  }

  @Test
  public void whenEmptyIssuerSpecified_returns401_andAuditsRequest() throws Exception {
    this.mockMvc.perform(post("/api/v1/data?name=/picard")
        .header("Authorization", "Bearer " + EMPTY_ISSUER_JWT)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error_description").value(ERROR_MESSAGE));

    auditingHelper.verifyRequestAuditing("/api/v1/data", 401);
  }
}
