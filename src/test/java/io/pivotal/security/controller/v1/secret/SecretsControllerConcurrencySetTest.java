package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;

@RunWith(Spectrum.class)
@ActiveProfiles(profiles = {"unit-test", "UseRealAuditLogService"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerConcurrencySetTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  SecretsController subject;

  @Autowired
  private Encryptor encryptor;

  @SpyBean
  AuditLogService auditLogService;

  @SpyBean
  SecretDataService secretDataService;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private final Consumer<Long> fakeTimeSetter;

  private final String secretName = "/my-namespace/secretForSetTest/secret-name";

  private ResultActions response;

  private UUID uuid;
  final String secretValue = "secret-value";

  private ResultActions[] responses;

  {
    wireAndUnwire(this);

    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

      resetAuditLogMock();
    });

    describe("setting secrets in parallel", () -> {
      beforeEach(() -> {
        responses = new ResultActions[2];

        Thread thread1 = new Thread("thread 1") {
          @Override
          public void run() {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"value\"," +
                    "  \"name\":\"" + secretName + this.getName() + "\"," +
                    "  \"value\":\"" + secretValue + this.getName() + "\"" +
                    "}");

            try {
              responses[0] = mockMvc.perform(put);
            } catch (Exception e) {
              e.printStackTrace();
            }
          }
        };
        Thread thread2 = new Thread("thread 2") {
          @Override
          public void run() {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"value\"," +
                    "  \"name\":\"" + secretName + this.getName() + "\"," +
                    "  \"value\":\"" + secretValue + this.getName() + "\"" +
                    "}");

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

      it("test", () -> {
        responses[0].andExpect(jsonPath("$.value").value(secretValue + "thread 1"));
        responses[1].andExpect(jsonPath("$.value").value(secretValue + "thread 2"));
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
          valueSecret.setVersionCreatedAt(frozenTime);

          doReturn(null)
              .doReturn(valueSecret)
              .when(secretDataService).findMostRecent(anyString());

          doThrow(new DataIntegrityViolationException("we already have one of those"))
              .when(secretDataService).save(any(NamedSecret.class));

          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"value\"," +
                  "  \"name\":\"" + secretName + "\"," +
                  "  \"value\":\"" + secretValue + "\"" +
                  "}");

          response = mockMvc.perform(put);
        });

        it("retries and finds the value written by the other thread", () -> {
          verify(secretDataService).save(any(NamedSecret.class));
          response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("value"))
              .andExpect(jsonPath("$.value").value(secretValue))
              .andExpect(jsonPath("$.id").value(uuid.toString()))
              .andExpect(jsonPath("$.version_created_at").value(frozenTime.toString()));
        });
      });
    });
  }

  private void resetAuditLogMock() throws Exception {
    reset(auditLogService);
    doAnswer(invocation -> {
      final Supplier action = invocation.getArgumentAt(1, Supplier.class);
      return action.get();
    }).when(auditLogService).performWithAuditing(isA(AuditRecordBuilder.class), isA(Supplier.class));
  }
}
