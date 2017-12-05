package org.cloudfoundry.credhub.controller.v1;

import com.google.common.collect.ImmutableMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping(produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class InfoController {
  private static final String CREDHUB_NAME = "CredHub";

  private final String uaaUrl;

  @Autowired
  InfoController(
      @Value("${auth_server.url:}") String uaaUrl
  ) {
    this.uaaUrl = uaaUrl;
  }

  @RequestMapping(method = RequestMethod.GET, path = "/info")
  public Map<String, ?> info() {

    return ImmutableMap.of(
        "auth-server", ImmutableMap.of("url", uaaUrl),
        "app", ImmutableMap.of(
            "name", CREDHUB_NAME
        ));
  }
}
