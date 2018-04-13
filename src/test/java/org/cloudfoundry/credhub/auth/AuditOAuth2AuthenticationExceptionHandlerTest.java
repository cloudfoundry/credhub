package org.cloudfoundry.credhub.auth;

import org.cloudfoundry.credhub.entity.AuthFailureAuditRecord;
import org.cloudfoundry.credhub.repository.AuthFailureAuditRecordRepository;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
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
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.Map;

import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.when;
import static org.springframework.data.domain.Sort.Direction.DESC;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest
@Transactional
public class AuditOAuth2AuthenticationExceptionHandlerTest {

  private static final String CREDENTIAL_URL_PATH = "/api/v1/data/foo";
  private static final String CREDENTIAL_URL_QUERY_PARAMS = "?my_name=my_value";
  private static final String CREDENTIAL_URL = String.join("", CREDENTIAL_URL_PATH, CREDENTIAL_URL_QUERY_PARAMS);
  private static final Instant NOW = Instant.ofEpochSecond(1490903353);

  @Autowired
  private WebApplicationContext applicationContext;

  @Autowired
  private AuthFailureAuditRecordRepository authFailureAuditRecordRepository;

  @Autowired
  private ResourceServerTokenServices tokenServices;

  @MockBean
  private CurrentTimeProvider currentTimeProvider;

  private MockMvc mockMvc;

  @Before
  public void setUp() {
    when(currentTimeProvider.getInstant()).thenReturn(NOW);
    when(currentTimeProvider.getNow()).thenReturn(CurrentTimeProvider.makeCalendar(NOW.toEpochMilli()));

    mockMvc = MockMvcBuilders
        .webAppContextSetup(applicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void whenTheTokenIsValid_logsTheCorrectExceptionToTheDatabase() throws Exception {
    mockMvc.perform(get(CREDENTIAL_URL)
        .header("Authorization", "Bearer " + AuthConstants.INVALID_JSON_JWT)
        .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .with(request -> {
          request.setRemoteAddr("99.99.99.99");
          return request;
        }));

    AuthFailureAuditRecord auditRecord = authFailureAuditRecordRepository
        .findAll(new Sort(DESC, "now")).get(0);
    assertThat(auditRecord.getPath(), equalTo(CREDENTIAL_URL_PATH));
    assertThat(auditRecord.getAuthMethod(), equalTo(UserContext.AUTH_METHOD_UAA));
    assertThat(auditRecord.getQueryParameters(), equalTo("my_name=my_value"));
    assertThat(auditRecord.getRequesterIp(), equalTo("99.99.99.99"));
    assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
    assertThat(auditRecord.getFailureDescription(), equalTo("Cannot convert access token to JSON"));
    assertThat(auditRecord.getUserId(), equalTo(null));
    assertThat(auditRecord.getUserName(), equalTo(null));
    assertThat(auditRecord.getUaaUrl(), equalTo(null));
    assertThat(auditRecord.getAuthValidFrom(), equalTo(-1L));
    assertThat(auditRecord.getAuthValidUntil(), equalTo(-1L));
    assertThat(auditRecord.getClientId(), equalTo(null));
    assertThat(auditRecord.getScope(), equalTo(null));
    assertThat(auditRecord.getGrantType(), equalTo(null));
    assertThat(auditRecord.getMethod(), equalTo("GET"));
    assertThat(auditRecord.getStatusCode(), equalTo(401));
  }

  @Test
  public void whenTheTokenHasBeenSignedWithAMismatchedRsaKey_providesAHumanFriendlyResponse() throws Exception {
    String errorMessage = "The request token signature could not be verified. Please validate that your request token was issued by the UAA server authorized by CredHub.";

    mockMvc.perform(get(CREDENTIAL_URL)
        .header("Authorization", "Bearer " + AuthConstants.INVALID_SIGNATURE_JWT)
        .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error").value("invalid_token"))
        .andExpect(jsonPath("$.error_description").value(errorMessage));
  }

  @Test
  public void whenTheTokenHasExpired_returnsTheCorrectError_andCleansTheTokenFromTheErroDescriptionField() throws Exception {
    mockMvc.perform(get(CREDENTIAL_URL)
        .header("Authorization", "Bearer " + AuthConstants.EXPIRED_KEY_JWT)
        .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error").value("access_token_expired"))
        .andExpect(jsonPath("$.error_description").value("Access token expired"));
  }

  @Test
  public void whenTheTokenHasExpired_savesTheCorrectExceptionToTheDatabase() throws Exception {
    mockMvc.perform(get(CREDENTIAL_URL)
        .header("Authorization", "Bearer " + AuthConstants.EXPIRED_KEY_JWT)
        .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .with(request -> {
          request.setRemoteAddr("99.99.99.99");
          return request;
        }));

    AuthFailureAuditRecord auditRecord = authFailureAuditRecordRepository.findAll(new Sort(DESC, "now")).get(0);

    assertThat(auditRecord.getNow(), equalTo(NOW));
    assertThat(auditRecord.getPath(), equalTo(CREDENTIAL_URL_PATH));
    assertThat(auditRecord.getQueryParameters(), equalTo("my_name=my_value"));
    assertThat(auditRecord.getRequesterIp(), equalTo("99.99.99.99"));
    assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
    assertThat(auditRecord.getFailureDescription(), equalTo("Access token expired"));

    OAuth2AccessToken accessToken = tokenServices.readAccessToken(AuthConstants.EXPIRED_KEY_JWT);
    Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();

    assertThat(auditRecord.getUserId(), equalTo(additionalInformation.get("user_id")));
    assertThat(auditRecord.getUserName(), equalTo(additionalInformation.get("user_name")));
    assertThat(auditRecord.getUaaUrl(), equalTo(additionalInformation.get("iss")));
    assertThat(auditRecord.getAuthValidFrom(),
        equalTo(((Number) additionalInformation.get("iat")).longValue())); // 1469051704L
    assertThat(auditRecord.getAuthValidUntil(),
        equalTo(accessToken.getExpiration().toInstant().getEpochSecond())); // 1469051824L
    assertThat(auditRecord.getClientId(), equalTo("credhub_cli"));
    assertThat(auditRecord.getScope(), equalTo("credhub.write,credhub.read"));
    assertThat(auditRecord.getGrantType(), equalTo("password"));
    assertThat(auditRecord.getMethod(), equalTo("GET"));
    assertThat(auditRecord.getStatusCode(), equalTo(401));
  }

  @Test
  public void whenThereIsNoToken_logsTheCorrectExceptionToTheDatabase() throws Exception {
    mockMvc.perform(get(CREDENTIAL_URL)
        .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .with(request -> {
          request.setRemoteAddr("12346");
          return request;
        }));

    AuthFailureAuditRecord auditRecord = authFailureAuditRecordRepository.findAll(new Sort(DESC, "now")).get(0);

    assertThat(auditRecord.getNow(), equalTo(NOW));
    assertThat(auditRecord.getPath(), equalTo(CREDENTIAL_URL_PATH));
    assertThat(auditRecord.getAuthMethod(), equalTo(UserContext.AUTH_METHOD_UAA));
    assertThat(auditRecord.getQueryParameters(), equalTo("my_name=my_value"));
    assertThat(auditRecord.getRequesterIp(), equalTo("12346"));
    assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
    assertThat(auditRecord.getFailureDescription(),
        equalTo("Full authentication is required to access this resource"));
    assertThat(auditRecord.getUserId(), nullValue());
    assertThat(auditRecord.getUserName(), nullValue());
    assertThat(auditRecord.getUaaUrl(), nullValue());
    assertThat(auditRecord.getAuthValidFrom(), equalTo(-1L));
    assertThat(auditRecord.getAuthValidUntil(), equalTo(-1L));
    assertThat(auditRecord.getClientId(), equalTo(null));
    assertThat(auditRecord.getScope(), equalTo(null));
    assertThat(auditRecord.getGrantType(), equalTo(null));
    assertThat(auditRecord.getMethod(), equalTo("GET"));
    assertThat(auditRecord.getStatusCode(), equalTo(401));
  }
}
