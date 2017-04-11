package io.pivotal.security.controller.v1.secret;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.request.AccessControlOperation.DELETE;
import static io.pivotal.security.request.AccessControlOperation.READ;
import static io.pivotal.security.request.AccessControlOperation.READ_ACL;
import static io.pivotal.security.request.AccessControlOperation.WRITE;
import static io.pivotal.security.request.AccessControlOperation.WRITE_ACL;
import static io.pivotal.security.util.AuditLogTestHelper.resetAuditLogMock;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.google.common.collect.ImmutableMap;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.helper.JsonHelper;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.AccessControlListResponse;
import io.pivotal.security.view.ValueView;
import java.util.UUID;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(Spectrum.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerConcurrencySetTest {

  final String secretValue = "secret-value";
  private final String secretName = "/my-namespace/secretForSetTest/secret-name";
  @Autowired
  WebApplicationContext webApplicationContext;
  @Autowired
  SecretsController subject;
  @SpyBean
  AuditLogService auditLogService;
  @SpyBean
  SecretDataService secretDataService;
  @Autowired
  private Encryptor encryptor;
  private MockMvc mockMvc;
  private ResultActions response;
  private UUID uuid;
  private ResultActions[] responses;
  private String winningActor;

  private AuditRecordBuilder auditRecordBuilder;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();

      auditRecordBuilder = new AuditRecordBuilder();
      resetAuditLogMock(auditLogService, auditRecordBuilder);
    });

    describe("setting secrets in parallel", () -> {
      beforeEach(() -> {
        responses = new ResultActions[2];

        Thread thread1 = new Thread("thread1") {
          @Override
          public void run() {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{"
                    + "\"type\":\"value\","
                    + "\"overwrite\":false,"
                    + "\"name\":\"" + secretName + "\","
                    + "\"value\":\"uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d\","
                    + "\"access_control_entries\":[{"
                    + "\"actor\":\"mtls:app:uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d\","
                    + "\"operations\": [\"read\"]"
                    + "}]"
                    + "}");

            try {
              responses[0] = mockMvc.perform(put);
            } catch (Exception e) {
              e.printStackTrace();
            }
          }
        };
        Thread thread2 = new Thread("thread2") {
          @Override
          public void run() {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{"
                    + "\"type\":\"value\","
                    + "\"overwrite\":false,"
                    + "\"name\":\"" + secretName + "\","
                    + "\"value\":\"uaa-client:credhub_test\","
                    + "\"access_control_entries\":[{"
                    + "\"actor\":\"mtls:app:uaa-client:credhub_test\","
                    + "\"operations\": [\"read\"]"
                    + "}]"
                    + "}");

            try {
              responses[1] = mockMvc.perform(put);
            } catch (Exception e) {
              e.printStackTrace();
            }
          }
        };

        thread1.start();
        thread2.start();
        thread1.join();
        thread2.join();
      });

      it("should allow only one thread to write credential value", () -> {
        MvcResult result1 = responses[0]
            .andDo(print())
            .andReturn();
        ValueView value1 = JsonHelper.deserialize(result1.getResponse().getContentAsString(), ValueView.class);
        MvcResult result2 = responses[1]
            .andDo(print())
            .andReturn();
        ValueView value2 = JsonHelper.deserialize(result2.getResponse().getContentAsString(), ValueView.class);

        assertThat(value1.getValue(), equalTo(value2.getValue()));
        winningActor = (String) value1.getValue();
      });

      it("should set ACEs of the winning thread only", () -> {
        String tokenForWinningActor = ImmutableMap
            .of("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", UAA_OAUTH2_PASSWORD_GRANT_TOKEN,
                "uaa-client:credhub_test", UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
            .get(winningActor);

        MvcResult result = mockMvc.perform(get("/api/v1/acls?credential_name=" + secretName)
            .header("Authorization", "Bearer " + tokenForWinningActor))
            .andExpect(status().isOk())
            .andDo(print())
            .andReturn();
        String content = result.getResponse().getContentAsString();
        AccessControlListResponse acl = JsonHelper.deserialize(content, AccessControlListResponse.class);
        assertThat(acl.getAccessControlList(), containsInAnyOrder(
            samePropertyValuesAs(
                new AccessControlEntry(winningActor,
                    asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
            samePropertyValuesAs(
                new AccessControlEntry("mtls:app:" + this.winningActor, asList(READ)))
        ));
      });
    });

    describe("setting a secret", () -> {
      describe("when another thread wins a race to write a new value", () -> {
        beforeEach(() -> {
          uuid = UUID.randomUUID();

          NamedValueSecret valueSecret = new NamedValueSecret(secretName);
          valueSecret.setEncryptor(encryptor);
          valueSecret.setValue(secretValue);
          valueSecret.setUuid(uuid);

          doReturn(null)
              .doReturn(valueSecret)
              .when(secretDataService).findMostRecent(anyString());

          doThrow(new DataIntegrityViolationException("we already have one of those"))
              .when(secretDataService).save(any(NamedSecret.class));

          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{"
                  + "\"type\":\"value\","
                  + "\"name\":\"" +secretName + "\","
                  + "\"value\":\"" + secretValue
                  + "\"}");

          response = mockMvc.perform(put);
        });

        it("retries and finds the value written by the other thread", () -> {
          verify(secretDataService).save(any(NamedSecret.class));
          response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("value"))
              .andExpect(jsonPath("$.value").value(secretValue))
              .andExpect(jsonPath("$.id").value(uuid.toString()));
        });
      });
    });
  }
}
