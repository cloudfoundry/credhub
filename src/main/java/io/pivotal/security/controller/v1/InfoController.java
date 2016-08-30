package io.pivotal.security.controller.v1;

import com.google.common.collect.ImmutableMap;
import io.pivotal.security.config.AuthServerProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@SuppressWarnings("unused")
@RestController
@RequestMapping(produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class InfoController {

  @Autowired
  AuthServerProperties authServerProperties;

  @Autowired
  Environment environment;

  @RequestMapping(method = RequestMethod.GET, path = "/info")
  public Map<String, ?> info() {
    String version;
    try {
      version = environment.getProperty("info.app.version");
    } catch (IllegalArgumentException e) {
      version = "dev";
    }

    return ImmutableMap.of(
        "auth-server", ImmutableMap.of("url", authServerProperties.getUrl()),
        "app", ImmutableMap.of(
            "name", environment.getProperty("info.app.name"),
            "version", version
        ));
  }
}
