package org.cloudfoundry.credhub.generate;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import org.cloudfoundry.credhub.exceptions.PermissionException;
import org.cloudfoundry.credhub.testdoubles.RegenerateHandler;
import org.cloudfoundry.credhub.requests.BulkRegenerateRequest;
import org.cloudfoundry.credhub.requests.RegenerateRequest;
import org.cloudfoundry.credhub.views.BulkRegenerateResults;
import org.cloudfoundry.credhub.views.CredentialView;

@RestController
public class RegenerateController {

  public static final String API_V1_REGENERATE = "api/v1/regenerate";
  public static final String API_V1_BULK_REGENERATE = "api/v1/bulk-regenerate";

  private final RegenerateHandler regenerateHandler;

  @Autowired
  public RegenerateController(final RegenerateHandler regenerateHandler) {
    super();
    this.regenerateHandler = regenerateHandler;
  }

  @PostMapping(
    path = RegenerateController.API_V1_REGENERATE,
    produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView regenerate(@RequestBody @Validated final RegenerateRequest requestBody) {
    return regenerateHandler.handleRegenerate(requestBody.getName());
  }

  @PostMapping(
    path = RegenerateController.API_V1_BULK_REGENERATE,
    produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  @Transactional(rollbackFor = PermissionException.class)
  public BulkRegenerateResults bulkRegenerate(@RequestBody @Valid final BulkRegenerateRequest requestBody) {
    return regenerateHandler.handleBulkRegenerate(requestBody.getSignedBy());
  }
}
