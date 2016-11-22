package io.pivotal.security.oauth;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.OperationAuditRecordDataService;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.service.SecurityEventsLogService;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.Filter;
import java.time.Instant;
import java.util.Map;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.config.NoExpirationSymmetricKeySecurityConfiguration.INVALID_SCOPE_SYMMETRIC_KEY_JWT;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test", "NoExpirationSymmetricKeySecurityConfiguration"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class AuditOAuth2AccessDeniedHandlerTest {

  @Autowired
  WebApplicationContext applicationContext;

  @Autowired
  Filter springSecurityFilterChain;

  @Autowired
  AuditOAuth2AccessDeniedHandler subject;

  @MockBean
  OperationAuditRecordDataService operationAuditRecordDataService;

  @Autowired
  ResourceServerTokenServices tokenServices;

  @MockBean
  CurrentTimeProvider currentTimeProvider;

  @MockBean
  SecurityEventsLogService securityEventsLogService;

  private MockHttpServletRequestBuilder get;

  private MockMvc mockMvc;

  private Instant now;

  private final String credentialUrlPath = "/api/v1/data/foo";
  private final String credentialUrlQueryParams = "?query=value";
  private final String credentialUrl = String.join("", credentialUrlPath, credentialUrlQueryParams);

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      now = Instant.now();
      when(currentTimeProvider.getInstant()).thenReturn(now);

      mockMvc = MockMvcBuilders
          .webAppContextSetup(applicationContext)
          .addFilter(springSecurityFilterChain)
          .build();
    });

    describe("when the scope is invalid", () -> {
      beforeEach(() -> {
        String bearer = "Bearer " + INVALID_SCOPE_SYMMETRIC_KEY_JWT;
        get = get(credentialUrl)
            .header("Authorization", bearer)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .with(request -> {
              request.setRemoteAddr("12346");
              return request;
            });
        mockMvc.perform(get);
      });

      it("should log the failure in the operation_audit_record table", () -> {
        OAuth2AccessToken accessToken = tokenServices.readAccessToken(INVALID_SCOPE_SYMMETRIC_KEY_JWT);
        Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();

        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);
        verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

        OperationAuditRecord auditRecord = recordCaptor.getValue();

        assertThat(auditRecord.isSuccess(), equalTo(false));
        assertThat(auditRecord.getNow(), equalTo(now));
        assertThat(auditRecord.getPath(), equalTo(credentialUrlPath));
        assertThat(auditRecord.getQueryParameters(), equalTo("query=value"));
        assertThat(auditRecord.getOperation(), equalTo("credential_access"));
        assertThat(auditRecord.getRequesterIp(), equalTo("12346"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
        assertThat(auditRecord.getUserId(), equalTo(additionalInformation.get("user_id")));
        assertThat(auditRecord.getUserName(), equalTo(additionalInformation.get("user_name")));
        assertThat(auditRecord.getUaaUrl(), equalTo(additionalInformation.get("iss")));
        assertThat(auditRecord.getTokenIssued(), equalTo(((Number) additionalInformation.get("iat")).longValue())); // 2737304753L (year 2056)
        assertThat(auditRecord.getTokenExpires(), equalTo(accessToken.getExpiration().toInstant().getEpochSecond())); // 2737304773L (year 2056)
        assertThat(auditRecord.getClientId(), equalTo("credhub"));
        assertThat(auditRecord.getScope(), equalTo("credhub.bad_scope"));
        assertThat(auditRecord.getGrantType(), equalTo("password"));
        assertThat(auditRecord.getMethod(), equalTo("GET"));
        assertThat(auditRecord.getStatusCode(), equalTo(403));
      });

      it("should log the failure in the CEF syslog file", () -> {
        verify(securityEventsLogService).log(isA(OperationAuditRecord.class));
      });
    });
  }
}
