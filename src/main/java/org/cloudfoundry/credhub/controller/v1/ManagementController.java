package org.cloudfoundry.credhub.controller.v1;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.entity.Management;
import org.cloudfoundry.credhub.variables.ManagementVariables;

@RestController
@RequestMapping(
  path = ManagementController.MANAGEMENT,
  produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class ManagementController {
  public static final String MANAGEMENT = "management";
  private static final Logger LOGGER = LogManager.getLogger(ManagementController.class);

  @RequestMapping(path = "", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public Management getManagement() {
    return new Management(ManagementVariables.readOnlyMode);
  }

  @RequestMapping(path = "", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public Management setManagement(@RequestBody Management management) {
    ManagementVariables.readOnlyMode = management.isReadOnlyMode();
    LOGGER.info("Setting read only mode to " + management.isReadOnlyMode());
    return management;
  }
}
