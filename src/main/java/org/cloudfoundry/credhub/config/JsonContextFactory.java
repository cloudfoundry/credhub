package org.cloudfoundry.credhub.config;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.jayway.jsonpath.ParseContext;
import org.springframework.stereotype.Component;

@Component
public class JsonContextFactory {
  public ParseContext getParseContext() {
    Configuration configuration = Configuration.defaultConfiguration()
        .addOptions(Option.SUPPRESS_EXCEPTIONS);
    return JsonPath.using(configuration);
  }
}
