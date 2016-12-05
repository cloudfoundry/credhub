package io.pivotal.security.config;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.jayway.jsonpath.ParseContext;
import org.springframework.beans.factory.FactoryBean;

public class JsonContextFactory implements FactoryBean<ParseContext> {
  @Override
  public ParseContext getObject() throws Exception {
    Configuration configuration = Configuration.defaultConfiguration()
        .addOptions(Option.SUPPRESS_EXCEPTIONS);
    return JsonPath.using(configuration);
  }

  @Override
  public Class<?> getObjectType() {
    return ParseContext.class;
  }

  @Override
  public boolean isSingleton() {
    return false;
  }
}
