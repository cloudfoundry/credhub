package io.pivotal.security.integration;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.function.Consumer;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class NoOverwriteTest {
  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private ResultActions[] responses;
  private Thread thread1;
  private Thread thread2;
  private MockMvc mockMvc;
  private Consumer<Long> fakeTimeSetter;

  private final String SECRET_NAME = "TEST-SECRET";
  private final Instant FROZEN_TIME = Instant.ofEpochSecond(1400011001L);

  {
    wireAndUnwire(this, true);

    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      encryptionKeyCanaryMapper.mapUuidsToKeys();
      fakeTimeSetter.accept(FROZEN_TIME.toEpochMilli());
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    });

    describe("when multiple threads attempt to create a secret with the same name with no-overwrite", () -> {
      beforeEach(()->{
        responses = new ResultActions[2];

        thread1 = new Thread("thread 1") {
          @Override
          public void run() {
            final MockHttpServletRequestBuilder putRequest = put("/api/v1/data")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"value\"," +
                    "  \"name\":\"" + SECRET_NAME + "\"," +
                    "  \"value\":\"first-value\"" +
                    "}");

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
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"value\"," +
                    "  \"name\":\"" + SECRET_NAME +"\"," +
                    "  \"value\":\"second-value\"" +
                    "}");

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

        DocumentContext response1 = JsonPath.parse(responses[0].andReturn().getResponse().getContentAsString());
        DocumentContext response2 = JsonPath.parse(responses[1].andReturn().getResponse().getContentAsString());

        assertThat(response2.read("$.value").equals(response1.read("$.value")));
      });
    });
  }
}
