package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedValueSecret;
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
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

@RunWith(Spectrum.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerConcurrencySetTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  SecretsController subject;

  @SpyBean
  SecretDataService secretDataService;

  @Autowired
  private Encryptor encryptor;

  private final String secretName = "/my-namespace/secretForSetTest/secret-name";
  private final String secretValue = "secret-value";
  private MockMvc mockMvc;
  private ResultActions response;
  private UUID uuid;
  private ResultActions[] responses;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();
    });

    describe("setting secrets in parallel", () -> {
      beforeEach(() -> {
        responses = new ResultActions[2];

        Thread thread1 = new Thread("thread 1") {
          @Override
          public void run() {
            final MockHttpServletRequestBuilder putReq = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{"
                    + "  \"type\":\"value\","
                    + "  \"name\":\""
                    + secretName + this.getName() + "\",  \"value\":\""
                    + secretValue + this.getName() + "\"}");

            try {
              responses[0] = mockMvc.perform(putReq);
            } catch (Exception e) {
              e.printStackTrace();
            }
          }
        };
        Thread thread2 = new Thread("thread 2") {
          @Override
          public void run() {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{"
                    + "  \"type\":\"value\","
                    + "  \"name\":\""
                    + secretName + this.getName() + "\",  \"value\":\""
                    + secretValue + this.getName() + "\"}");

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
        responses[0].andExpect(jsonPath("$.value").value(secretValue
            + "thread 1"));
        responses[1].andExpect(jsonPath("$.value").value(secretValue
            + "thread 2"));
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
