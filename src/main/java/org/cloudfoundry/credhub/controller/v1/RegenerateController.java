package org.cloudfoundry.credhub.controller.v1;

import org.cloudfoundry.credhub.exceptions.PermissionException;
import org.cloudfoundry.credhub.handler.RegenerateHandler;
import org.cloudfoundry.credhub.request.BulkRegenerateRequest;
import org.cloudfoundry.credhub.request.RegenerateRequest;
import org.cloudfoundry.credhub.view.BulkRegenerateResults;
import org.cloudfoundry.credhub.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
public class RegenerateController {

  static final String API_V1_REGENERATE = "api/v1/regenerate";
  static final String API_V1_BULK_REGENERATE = "api/v1/bulk-regenerate";

  private RegenerateHandler regenerateHandler;

  @Autowired
  public RegenerateController(RegenerateHandler regenerateHandler) {
    this.regenerateHandler = regenerateHandler;
  }

  @PostMapping(
      path = RegenerateController.API_V1_REGENERATE,
      produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView regenerate(@RequestBody @Validated RegenerateRequest requestBody) {
    return regenerateHandler.handleRegenerate(requestBody.getName());
  }

  @PostMapping(
      path = RegenerateController.API_V1_BULK_REGENERATE,
      produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  @Transactional(rollbackFor=PermissionException.class)
  public BulkRegenerateResults bulkRegenerate(@RequestBody @Valid BulkRegenerateRequest requestBody) {
    return regenerateHandler.handleBulkRegenerate(requestBody.getSignedBy());
  }
}
