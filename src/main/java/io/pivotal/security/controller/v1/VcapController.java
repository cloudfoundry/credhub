package io.pivotal.security.controller.v1;

import com.google.common.collect.Maps;
import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.config.JsonContextFactory;
import net.minidev.json.JSONArray;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;

@SuppressWarnings("unused")
@RestController
@RequestMapping(path = VcapController.API_V1, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class VcapController {
  public static final String API_V1 = "/api/v1";
  private final JsonContextFactory jsonContextFactory;


  @Autowired
  VcapController(JsonContextFactory jsonContextFactory) {
    this.jsonContextFactory = jsonContextFactory;
  }

  @RequestMapping(method = RequestMethod.POST, path = "/vcap")
  public ResponseEntity interpolate(InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    DocumentContext requestJson = parseToJson(requestBody);

    Map<String, Object> requestAsMap = requestJson.json();
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

    return new ResponseEntity(requestJson.jsonString(), HttpStatus.OK);
  }

  private DocumentContext parseToJson(InputStream requestBody) throws Exception {
    return jsonContextFactory.getObject().parse(requestBody);
  }
}
