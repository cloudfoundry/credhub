package io.pivotal.security.controller.v1;

import io.pivotal.security.audit.EventAuditLogService;
import io.pivotal.security.audit.RequestUuid;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.service.JsonInterpolationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@SuppressWarnings("unused")
@RestController
@RequestMapping(path = InterpolationController.API_V1, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class InterpolationController {

  static final String API_V1 = "/api/v1";
  private final JsonInterpolationService jsonInterpolationService;
  private final EventAuditLogService eventAuditLogService;

  @Autowired
  InterpolationController(
      JsonInterpolationService jsonInterpolationService,
      EventAuditLogService eventAuditLogService
  ) {
    this.jsonInterpolationService = jsonInterpolationService;
    this.eventAuditLogService = eventAuditLogService;
  }

  @RequestMapping(method = RequestMethod.POST, path = "/interpolate")
  @ResponseStatus(HttpStatus.OK)
  public Map<String, Object> interpolate(@RequestBody Map<String, Object> requestBody,
      RequestUuid requestUuid,
      UserContext userContext) {
    return eventAuditLogService.auditEvents(requestUuid, userContext, (eventAuditRecordParameters ->
          jsonInterpolationService
            .interpolateCredHubReferences(requestBody, eventAuditRecordParameters))
    );
  }
}
