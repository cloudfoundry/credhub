package io.pivotal.security;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.JsonPath;
import org.junit.runner.RunWith;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.Optional;

import static com.greghaskins.spectrum.Spectrum.*;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

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
        final String buildNumber = Optional.ofNullable(System.getenv("BUILD_NUMBER")).orElse("DEV");
        Object expected = JsonPath.parse("{" +
            "\"app\":" +
            "{\"name\":\"Pivotal Credential Manager\"," +
            "\"version\":\"0.1.0 build " + buildNumber + "\"" +
            "}" +
            "}")
            .json();

        final ResponseEntity<String> response = restTemplate.getForEntity(APP_URL + "/info", String.class);

        assertThat(response.getStatusCode(), equalTo(HttpStatus.OK));
        assertThat(JsonPath.parse(response.getBody()).json(), equalTo(expected));
      });
    });

    afterEach(() -> {
      server.value.destroy();
    });
  }

}