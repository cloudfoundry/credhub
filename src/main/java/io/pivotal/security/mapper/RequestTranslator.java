package io.pivotal.security.mapper;

import static com.jayway.jsonpath.JsonPath.using;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.Option;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.util.StringUtil;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public interface RequestTranslator<ET> {

  static void validatePathName(String name) {
    if (name.contains("//") || name.endsWith("/")) {
      throw new ParameterizedValidationException("error.invalid_name_has_slash");
    }
  }

  void populateEntityFromJson(ET namedSecret, DocumentContext documentContext);

  Set<String> getValidKeys();

  default void validateJsonKeys(DocumentContext parsed) {
    Set<String> keys = getValidKeys();
    Configuration conf = Configuration.builder().options(Option.AS_PATH_LIST).build();
    List<String> pathList = using(conf).parse(parsed.jsonString()).read("$..*");
    pathList = pathList.stream().map(StringUtil::convertJsonArrayRefToWildcard)
        .collect(Collectors.toList());
    pathList.removeAll(keys);
    if (pathList.size() > 0) {
      throw new ParameterizedValidationException("error.invalid_json_key", pathList.get(0));
    }
  }
}
