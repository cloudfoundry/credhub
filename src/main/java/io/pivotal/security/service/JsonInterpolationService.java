package io.pivotal.security.service;

import com.google.common.collect.Maps;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.InvalidJsonException;
import io.pivotal.security.config.JsonContextFactory;
import net.minidev.json.JSONArray;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class JsonInterpolationService {
  private final JsonContextFactory jsonContextFactory;

  public JsonInterpolationService(JsonContextFactory jsonContextFactory) {
    this.jsonContextFactory = jsonContextFactory;
  }

  public DocumentContext interpolateCredhubReferences(String requestBody) throws Exception {
    DocumentContext requestJson = parseToJson(requestBody);

    Object request = requestJson.json();
    if (! (request instanceof Map)) {
      throw new InvalidJsonException();
    }

    Map<String, Object> requestAsMap = (Map<String, Object>) request;
    Object vcapServices = requestAsMap.get("VCAP_SERVICES");
    if (vcapServices != null && vcapServices instanceof Map) {
      Map<String, Object> vcapServicesMap = (LinkedHashMap<String, Object>) vcapServices;
      for (Object serviceProperties : vcapServicesMap.values()) {
        if (! (serviceProperties instanceof JSONArray)) {
          continue;
        }
        JSONArray servicePropertiesAsArray = (JSONArray) serviceProperties;
        for (Object properties : servicePropertiesAsArray) {
          if (! (properties instanceof Map)) {
            continue;
          }
          Map<String, Object> propertiesMap = (Map<String, Object>) properties;
          Object credentials = propertiesMap.get("credentials");
          if (! (credentials instanceof Map)) {
            continue;
          }
          Map<String, Object> credentialsWrapper = (Map<String, Object>) credentials;
          if (credentialsWrapper != null && credentialsWrapper.get("credhub-ref") != null) {
            Map<String, String> bogusValue = Maps.newHashMap();
            bogusValue.put("something", "some value");
            propertiesMap.put("credentials", bogusValue);
          }
        }
      }
    }
    return requestJson;
  }

  private DocumentContext parseToJson(String requestBody) throws Exception {
    return jsonContextFactory.getObject().parse(requestBody);
  }
}
