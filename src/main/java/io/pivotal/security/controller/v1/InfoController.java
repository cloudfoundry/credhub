package io.pivotal.security.controller.v1;

import com.google.common.collect.ImmutableMap;
import io.pivotal.security.config.AuthServerProperties;
import io.pivotal.security.config.VersionProvider;
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
  private final AuthServerProperties authServerProperties;
  private final Environment environment;
  private final VersionProvider versionProvider;

  @Autowired
  InfoController(
      AuthServerProperties authServerProperties,
      Environment environment,
      VersionProvider versionProvider
  ) {
    this.authServerProperties = authServerProperties;
    this.environment = environment;
    this.versionProvider = versionProvider;
  }

  @RequestMapping(method = RequestMethod.GET, path = "/info")
  public Map<String, ?> info() {

    return ImmutableMap.of(
        "auth-server", ImmutableMap.of("url", authServerProperties.getUrl()),
        "app", ImmutableMap.of(
            "name", environment.getProperty("info.app.name"),
            "version", versionProvider.getVersion()
        ));
  }
}
