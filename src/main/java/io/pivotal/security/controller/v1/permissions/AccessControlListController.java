package io.pivotal.security.controller.v1.permissions;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.handler.AccessControlHandler;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.view.AccessControlListResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static io.pivotal.security.entity.AuditingOperationCode.ACL_ACCESS;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping(path = "/api/v1/acls", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class AccessControlListController {
  private final AccessControlHandler accessControlHandler;
  private final AuditLogService auditLogService;

  @Autowired
  public AccessControlListController(
    AccessControlHandler accessControlHandler,
    AuditLogService auditLogService
  ) {
    this.accessControlHandler = accessControlHandler;
    this.auditLogService = auditLogService;
  }

  @GetMapping
  public ResponseEntity<?> getAccessControlList(
    @RequestParam("credential_name") String credentialName,
    HttpServletRequest request,
    UserContext userContext
  ) throws Exception {
    return auditLogService.performWithAuditing(auditParams -> {
      auditParams.populateFromRequest(request);
      auditParams.setUserContext(userContext);
      auditParams.setCredentialName(credentialName);
      auditParams.setOperationCode(ACL_ACCESS);

      final AccessControlListResponse response = accessControlHandler.getAccessControlListResponse(userContext, credentialName);
      return new ResponseEntity<>(response, HttpStatus.OK);
    });
  }
}
