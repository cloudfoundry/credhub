package io.pivotal.security.controller.v1;

import com.google.common.collect.Lists;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.request.CredentialRegenerateRequest;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.service.RegenerateService;
import io.pivotal.security.view.CredentialView;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping(
    path = RegenerateController.API_V1_REGENERATE,
    produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class RegenerateController {
  public static final String API_V1_REGENERATE = "api/v1/regenerate";

  private static final Logger LOGGER = LogManager.getLogger(RegenerateController.class);
  private RegenerateService regenerateService;

  @Autowired
  public RegenerateController(RegenerateService regenerateService) {
    this.regenerateService = regenerateService;
  }

  @RequestMapping(path = "", method = RequestMethod.POST)
  @ResponseStatus(HttpStatus.OK)
  // TODO: retry logic
  // TODO: audit log
  public CredentialView regenerate(UserContext userContext,
                                   PermissionEntry currentUserPermissionEntry,
                                   @RequestBody CredentialRegenerateRequest requestBody) throws IOException {
    List<EventAuditRecordParameters> parametersList = Lists.newArrayList();
    requestBody.setRegenerate(true);
    return regenerateService
        .performRegenerate(userContext, parametersList, requestBody, currentUserPermissionEntry);
  }
}
