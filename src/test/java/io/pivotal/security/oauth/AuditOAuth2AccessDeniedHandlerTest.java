package io.pivotal.security.oauth;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.repository.AuditRecordRepository;
import io.pivotal.security.service.SecurityEventsLogService;
import io.pivotal.security.util.InstantFactoryBean;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.Filter;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.config.NoExpirationSymmetricKeySecurityConfiguration.INVALID_SCOPE_SYMMETRIC_KEY_JWT;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test", "NoExpirationSymmetricKeySecurityConfiguration"})
public class AuditOAuth2AccessDeniedHandlerTest {

  @Autowired
  WebApplicationContext applicationContext;

  @Autowired
  Filter springSecurityFilterChain;

  @Autowired
  @InjectMocks
  AuditOAuth2AccessDeniedHandler subject;

  @Autowired
  AuditRecordRepository operationAuditRecordRepository;

  @Autowired
  ResourceServerTokenServices tokenServices;

  @Mock
  InstantFactoryBean instantFactoryBean;

  @Mock
  SecurityEventsLogService securityEventsLogService;

  private MockHttpServletRequestBuilder get;

  private MockMvc mockMvc;

  private Instant now;

  private final String credentialUrlPath = "/api/v1/data/foo";
  private final String credentialUrlQueryParams = "?query=value";
  private final String credentialUrl = String.join("", credentialUrlPath, credentialUrlQueryParams);

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      now = Instant.now();
      when(instantFactoryBean.getObject()).thenReturn(now);

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

        List<OperationAuditRecord> auditRecords = operationAuditRecordRepository.findAll();

        assertThat(auditRecords.size(), equalTo(1));

        OperationAuditRecord auditRecord = auditRecords.get(0);

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
