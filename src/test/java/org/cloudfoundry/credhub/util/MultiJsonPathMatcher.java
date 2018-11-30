package org.cloudfoundry.credhub.util;

import org.springframework.test.web.servlet.ResultMatcher;

import com.jayway.jsonpath.JsonPath;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

final public class MultiJsonPathMatcher {

  private MultiJsonPathMatcher() {
  }

  public static ResultMatcher multiJsonPath(Object... keysAndValues) {
    return result -> {
      for (int i = 0; i < keysAndValues.length; ) {
        String jsonPath = (String) keysAndValues[i++];
        Object expectedValue = keysAndValues[i++];

        assertThat("field " + jsonPath, JsonPath.compile(jsonPath).read(result.getResponse().getContentAsString()),
          equalTo(expectedValue));
      }
    };
  }
}
