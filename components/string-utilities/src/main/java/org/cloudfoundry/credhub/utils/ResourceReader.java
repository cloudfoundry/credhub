package org.cloudfoundry.credhub.utils;

import java.io.IOException;
import java.net.URL;

import org.springframework.stereotype.Component;

import com.google.common.io.Resources;

@Component
public class ResourceReader {
  public String readFileToString(final String fileName) throws IOException {
    final URL resource = Resources.getResource(fileName);
    return Resources.toString(resource, StringUtil.UTF_8);
  }
}
