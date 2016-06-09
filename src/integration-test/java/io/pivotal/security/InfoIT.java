package io.pivotal.security;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static com.greghaskins.spectrum.Spectrum.value;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

import java.util.Optional;

@RunWith(Spectrum.class)
public class InfoIT {

  private String APP_URL = "http://localhost:8080";
  private final RestTemplate restTemplate = new RestTemplate();
  private Spectrum.Value<Process> server = value(Process.class);

  {
    beforeEach(() -> {
      ProcessBuilder processBuilder = new ProcessBuilder()
          .command("java", "-jar", Helper.jarPath());

      server.value = processBuilder.start();

      Helper.waitForServer(APP_URL);
    });

    describe("the info endpoint", () -> {
      it("responds with the app version", () -> {
        final ResponseEntity<String> response = restTemplate.getForEntity(APP_URL + "/info", String
            .class);

        final String buildNumber = Optional.ofNullable(System.getenv("BUILD_NUMBER")).orElse("DEV");

        assertThat(response.getStatusCode(), equalTo(HttpStatus.OK));
        assertThat(response.getBody(), equalTo("{" +
            "\"app\":{" +
            "\"name\":\"Pivotal Credential Manager\"," +
            "\"version\":\"0.1.0 build " + buildNumber + "\"" +
            "}" +
            "}"));
      });
    });

    afterEach(() -> {
      server.value.destroy();
    });
  }

}