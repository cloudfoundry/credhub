package org.cloudfoundry.credhub.util;

import java.io.IOException;
import java.net.URL;

import org.springframework.stereotype.Component;

import com.google.common.base.Charsets;
import com.google.common.io.Resources;

@Component
public class ResourceReader {
  public String readFileToString(String fileName) throws IOException {
    final URL resource = Resources.getResource(fileName);
    return Resources.toString(resource, Charsets.UTF_8);
  }
}
