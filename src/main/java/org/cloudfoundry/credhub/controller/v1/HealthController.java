package org.cloudfoundry.credhub.controller.v1;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.Map;

import static com.google.common.collect.ImmutableMap.of;

@Controller
public class HealthController {

  private CEFAuditRecord auditRecord;

  @Autowired
  public HealthController(CEFAuditRecord auditRecord) {
    this.auditRecord = auditRecord;
  }

  @RequestMapping(value = "/health", method = RequestMethod.GET)
  public ResponseEntity<Map> getHealth() {
    auditRecord.setRequestDetails(() -> OperationDeviceAction.HEALTH);
    try {
      return new ResponseEntity<>(of("status", "UP"), HttpStatus.OK);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
