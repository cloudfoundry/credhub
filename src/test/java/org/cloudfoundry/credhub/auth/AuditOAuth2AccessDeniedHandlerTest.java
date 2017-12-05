package org.cloudfoundry.credhub.auth;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.domain.SecurityEventAuditRecord;
import org.cloudfoundry.credhub.entity.RequestAuditRecord;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.cloudfoundry.credhub.service.SecurityEventsLogService;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.controller.v1.CredentialsController;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.Sort;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.verify;
import static org.springframework.data.domain.Sort.Direction.DESC;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class AuditOAuth2AccessDeniedHandlerTest {

  private static final String CREDENTIAL_URL_PATH = "/api/v1/data?name=foo";
  private static final String CREDENTIAL_URL_QUERY_PARAMS = "&query=value";
  private static final String CREDENTIAL_URL = String.join("", CREDENTIAL_URL_PATH, CREDENTIAL_URL_QUERY_PARAMS);

  @Autowired
  private WebApplicationContext applicationContext;
  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;
  @Autowired
  private DefaultTokenServices tokenServices;
  @MockBean
  private SecurityEventsLogService securityEventsLogService;
  private ResultActions response;

  @Before
  public void setUp() throws Exception {
    MockMvc mockMvc = MockMvcBuilders
        .webAppContextSetup(applicationContext)
        .apply(springSecurity())
        .build();

    String bearer = "Bearer " + AuthConstants.INVALID_SCOPE_KEY_JWT;
    MockHttpServletRequestBuilder getRequest = get(CREDENTIAL_URL)
        .header("Authorization", bearer)
        .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .with(request -> {
          request.setRemoteAddr("12346");
          return request;
        });

    response = mockMvc.perform(getRequest);
  }

  @Test
  public void logsTheFailureInTheRequestAuditRecordTable() {
    RequestAuditRecord auditRecord = requestAuditRecordRepository.findAll(new Sort(DESC, "now")).get(0);

    assertThat(auditRecord.getPath(), equalTo(CredentialsController.API_V1_DATA));
    assertThat(auditRecord.getQueryParameters(), equalTo("name=foo&query=value"));
    assertThat(auditRecord.getRequesterIp(), equalTo("12346"));
    assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));

    OAuth2AccessToken accessToken = tokenServices
        .readAccessToken(AuthConstants.INVALID_SCOPE_KEY_JWT);
    Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();

    assertThat(auditRecord.getUserId(), equalTo(additionalInformation.get("user_id")));
    assertThat(auditRecord.getUserName(), equalTo(additionalInformation.get("user_name")));
    assertThat(auditRecord.getUaaUrl(), equalTo(additionalInformation.get("iss")));
    assertThat(auditRecord.getAuthValidFrom(), equalTo(
        ((Number) additionalInformation.get("iat")).longValue())); // 2737304753L (year 2056)
    assertThat(auditRecord.getAuthValidUntil(), equalTo(
        accessToken.getExpiration().toInstant().getEpochSecond())); // 2737304773L (year 2056)
    assertThat(auditRecord.getClientId(), equalTo("credhub_cli"));
    assertThat(auditRecord.getScope(), equalTo("credhub.bad_scope"));
    assertThat(auditRecord.getGrantType(), equalTo("password"));
    assertThat(auditRecord.getMethod(), equalTo("GET"));
    assertThat(auditRecord.getStatusCode(), equalTo(403));
  }

  @Test
  public void logsTheFailureInTheCEFSystemLog() {
    verify(securityEventsLogService).log(isA(SecurityEventAuditRecord.class));
  }

  @Test
  public void providesAHumanReadableException() throws Exception {
    String expectedError = "The authenticated user does not have the required scopes to perform that action. Please update the client to include credhub.read and credhub.write then retry your request.";

    response
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.error_description").value(expectedError));
  }
}
