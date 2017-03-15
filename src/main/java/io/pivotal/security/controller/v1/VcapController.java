package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.InvalidJsonException;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.service.JsonInterpolationService;
import io.pivotal.security.view.ResponseError;
import org.apache.logging.log4j.core.util.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

@SuppressWarnings("unused")
@RestController
@RequestMapping(path = VcapController.API_V1, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class VcapController {

  private final SecretDataService secretDataService;
  private MessageSourceAccessor messageSourceAccessor;
  public static final String API_V1 = "/api/v1";
  private final JsonInterpolationService jsonInterpolationService;

  @Autowired
  VcapController(JsonInterpolationService jsonInterpolationService, MessageSource messageSource, SecretDataService secretDataService) {
    this.jsonInterpolationService = jsonInterpolationService;
    this.messageSourceAccessor = new MessageSourceAccessor(messageSource);
    this.secretDataService = secretDataService;
  }

  @RequestMapping(method = RequestMethod.POST, path = "/vcap")
  public ResponseEntity interpolate(InputStream requestBody, HttpServletRequest request, Authentication authentication) throws Exception {
    String requestAsString = IOUtils.toString(new InputStreamReader(requestBody));

    DocumentContext responseJson;
    try {
      responseJson = jsonInterpolationService.interpolateCredhubReferences(requestAsString, secretDataService);
    } catch (InvalidJsonException e) {
      return new ResponseEntity(HttpStatus.BAD_REQUEST);
    }

    return new ResponseEntity(responseJson.jsonString(), HttpStatus.OK);
  }

  @ExceptionHandler({ParameterizedValidationException.class})
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  public ResponseError handleInvalidTypeAccess(ParameterizedValidationException exception) throws IOException {
    String errorMessage = messageSourceAccessor.getMessage(exception.getMessage(), exception.getParameters());
    return new ResponseError(errorMessage);
  }
}
