package org.cloudfoundry.credhub.utils;

import org.springframework.test.web.servlet.ResultMatcher;

import com.jayway.jsonpath.JsonPath;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

final public class MultiJsonPathMatcher {

  private MultiJsonPathMatcher() {
    super();
  }

  public static ResultMatcher multiJsonPath(final Object... keysAndValues) {
    return result -> {
      for (int i = 0; i < keysAndValues.length; ) {
        final String jsonPath = (String) keysAndValues[i++];
        final Object expectedValue = keysAndValues[i++];

        assertThat("field " + jsonPath, JsonPath.compile(jsonPath).read(result.getResponse().getContentAsString()),
          equalTo(expectedValue));
      }
    };
  }
}
