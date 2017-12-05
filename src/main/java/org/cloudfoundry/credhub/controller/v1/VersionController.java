package org.cloudfoundry.credhub.controller.v1;

import com.google.common.collect.ImmutableMap;
import org.cloudfoundry.credhub.config.VersionProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping(produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class VersionController {
  private static final String CREDHUB_NAME = "CredHub";

  private final String credhubVersion;

  @Autowired
  VersionController(
      VersionProvider versionProvider
  ) {
    this.credhubVersion = versionProvider.currentVersion();
  }

  @RequestMapping(method = RequestMethod.GET, path = "/version")
  public Map<String, ?> version() {
    return ImmutableMap.of("version", credhubVersion);
  }
}
