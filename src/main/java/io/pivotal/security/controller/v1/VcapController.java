package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.config.JsonContextFactory;
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
    String credentialPath = requestJson.read("$.credentials.credential-ref");
    if (credentialPath == null) {
      return new ResponseEntity(HttpStatus.UNPROCESSABLE_ENTITY);
    }
    return new ResponseEntity(HttpStatus.OK);
  }

  private DocumentContext parseToJson(InputStream requestBody) throws Exception {
    return jsonContextFactory.getObject().parse(requestBody);
  }
}
