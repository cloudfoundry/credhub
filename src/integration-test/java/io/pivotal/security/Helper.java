package io.pivotal.security;

import org.springframework.http.HttpStatus;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.io.File;

public class Helper {
  public static String jarPath() {
    File libs = new File(System.getProperty("user.dir") + "/build/libs/");
    File[] matchingFiles = libs.listFiles((dir, name) -> {
      return name.endsWith(".jar");
    });
    return matchingFiles[0].getAbsolutePath();
  }

  public static void waitForServer(String APP_URL) throws InterruptedException {
    final RestTemplate restTemplate = new RestTemplate();
    boolean serverUp = false;
    while (!serverUp) {
      Thread.sleep(500);
      try {
        final HttpStatus status = restTemplate.getForEntity(APP_URL + "/health", String.class).getStatusCode();
        serverUp = status == HttpStatus.OK;
      } catch (ResourceAccessException e) {

      }
    }
  }
}
