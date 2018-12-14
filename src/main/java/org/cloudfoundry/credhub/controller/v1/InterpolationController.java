package org.cloudfoundry.credhub.controller.v1;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.entity.InterpolateCredentials;
import org.cloudfoundry.credhub.handler.InterpolationHandler;

@RestController
@RequestMapping(path = InterpolationController.API_V1, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class InterpolationController {

  public static final String API_V1 = "/api/v1";
  private final InterpolationHandler jsonInterpolationHandler;
  private final CEFAuditRecord auditRecord;

  @Autowired
  public InterpolationController(final InterpolationHandler jsonInterpolationHandler, final CEFAuditRecord auditRecord) {
    super();
    this.jsonInterpolationHandler = jsonInterpolationHandler;
    this.auditRecord = auditRecord;
  }

  @RequestMapping(method = RequestMethod.POST, path = "/interpolate")
  @ResponseStatus(HttpStatus.OK)
  public Map<String, Object> interpolate(@RequestBody final Map<String, Object> requestBody) {
    auditRecord.setRequestDetails(new InterpolateCredentials());
    return jsonInterpolationHandler.interpolateCredHubReferences(requestBody);
  }
}
