package io.pivotal.security.integration;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_TOKEN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import java.time.Instant;
import java.util.function.Consumer;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class NoOverwriteTest {

  private static final String SECRET_NAME = "TEST-SECRET";
  private static final Instant FROZEN_TIME = Instant.ofEpochSecond(1400011001L);
  @Autowired
  WebApplicationContext webApplicationContext;
  @Autowired
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;
  private ResultActions[] responses;
  private Thread thread1;
  private Thread thread2;
  private MockMvc mockMvc;
  private Consumer<Long> fakeTimeSetter;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

      encryptionKeyCanaryMapper.mapUuidsToKeys();
      fakeTimeSetter.accept(FROZEN_TIME.toEpochMilli());
      mockMvc = MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();
    });

    describe(
        "when multiple threads attempt to create a secret with the same name with no-overwrite",
        () -> {
          beforeEach(() -> {
            responses = new ResultActions[2];

            thread1 = new Thread("thread 1") {
              @Override
              public void run() {
                final MockHttpServletRequestBuilder putRequest = put("/api/v1/data")
                    .header("Authorization", "Bearer " + UAA_OAUTH2_TOKEN)
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON)
                    .content("{"
                        + "  \"type\":\"value\","
                        + "  \"name\":\""
                        + SECRET_NAME + "\",  \"value\":\"first-value\""
                        + "}");

                try {
                  responses[0] = mockMvc.perform(putRequest);
                } catch (Exception e) {
                  e.printStackTrace();
                }
              }
            };
            thread2 = new Thread("thread 2") {
              @Override
              public void run() {
                final MockHttpServletRequestBuilder putRequest = put("/api/v1/data")
                    .header("Authorization", "Bearer " + UAA_OAUTH2_TOKEN)
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON)
                    .content("{"
                        + "  \"type\":\"value\","
                        + "  \"name\":\""
                        + SECRET_NAME + "\",  \"value\":\"second-value\""
                        + "}");

                try {
                  responses[1] = mockMvc.perform(putRequest);
                } catch (Exception e) {
                  e.printStackTrace();
                }
              }
            };
          });

          it("should return the same value for both", () -> {
            thread1.start();
            thread2.start();
            thread1.join();
            thread2.join();

            DocumentContext response1 = JsonPath
                .parse(responses[0].andReturn().getResponse().getContentAsString());
            DocumentContext response2 = JsonPath
                .parse(responses[1].andReturn().getResponse().getContentAsString());

            assertThat(response2.read("$.value").equals(response1.read("$.value")));
          });
        });
  }
}
