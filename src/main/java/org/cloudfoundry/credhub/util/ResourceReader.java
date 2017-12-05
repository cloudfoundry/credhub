package org.cloudfoundry.credhub.util;

import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URL;

@Component
public class ResourceReader {
  public String readFileToString(String fileName) throws IOException {
    final URL resource = Resources.getResource(fileName);
    return Resources.toString(resource, Charsets.UTF_8);
  }
}
