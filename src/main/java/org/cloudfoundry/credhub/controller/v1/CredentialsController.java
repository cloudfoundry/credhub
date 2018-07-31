package org.cloudfoundry.credhub.controller.v1;

import com.google.common.io.ByteStreams;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.entity.DeleteCredential;
import org.cloudfoundry.credhub.audit.entity.FindCredential;
import org.cloudfoundry.credhub.audit.entity.GetCredential;
import org.cloudfoundry.credhub.audit.entity.RequestDetails;
import org.cloudfoundry.credhub.audit.entity.SetCredential;
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException;
import org.cloudfoundry.credhub.handler.CredentialsHandler;
import org.cloudfoundry.credhub.handler.LegacyGenerationHandler;
import org.cloudfoundry.credhub.handler.SetHandler;
import org.cloudfoundry.credhub.request.BaseCredentialSetRequest;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.cloudfoundry.credhub.view.CredentialView;
import org.cloudfoundry.credhub.view.DataResponse;
import org.cloudfoundry.credhub.view.FindCredentialResults;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

@RestController
@RequestMapping(
    path = CredentialsController.API_V1_DATA,
    produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class CredentialsController {

  public static final String API_V1_DATA = "/api/v1/data";

  private static final Logger LOGGER = LogManager.getLogger(CredentialsController.class);
  private final PermissionedCredentialService credentialService;
  private final SetHandler setHandler;
  private final CredentialsHandler credentialsHandler;
  private final LegacyGenerationHandler legacyGenerationHandler;
  private CEFAuditRecord auditRecord;

  @Autowired
  public CredentialsController(PermissionedCredentialService credentialService,
      CredentialsHandler credentialsHandler,
      SetHandler setHandler,
      LegacyGenerationHandler legacyGenerationHandler,
      CEFAuditRecord auditRecord) {
    this.credentialService = credentialService;
    this.credentialsHandler = credentialsHandler;
    this.setHandler = setHandler;
    this.legacyGenerationHandler = legacyGenerationHandler;
    this.auditRecord = auditRecord;
  }

  @RequestMapping(path = "", method = RequestMethod.POST)
  @ResponseStatus(HttpStatus.OK)
  public synchronized CredentialView generate(InputStream inputStream) throws IOException {
    InputStream requestInputStream = new ByteArrayInputStream(ByteStreams.toByteArray(inputStream));
    return legacyGenerationHandler.auditedHandlePostRequest(requestInputStream);
  }

  @RequestMapping(path = "", method = RequestMethod.PUT)
  @ResponseStatus(HttpStatus.OK)
  public synchronized CredentialView set(@RequestBody BaseCredentialSetRequest requestBody) {
    requestBody.validate();
    return auditedHandlePutRequest(requestBody);
  }

  @RequestMapping(path = "", method = RequestMethod.DELETE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void delete(@RequestParam(value = "name") String credentialName) {
    if (StringUtils.isEmpty(credentialName)) {
      throw new InvalidQueryParameterException("error.missing_query_parameter", "name");
    }

    String credentialNameWithPrependedSlash = StringUtils.prependIfMissing(credentialName, "/");

    RequestDetails requestDetails = new DeleteCredential(credentialNameWithPrependedSlash);
    auditRecord.setRequestDetails(requestDetails);

    credentialsHandler.deleteCredential(credentialNameWithPrependedSlash);
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView getCredentialById(@PathVariable String id) {
    return credentialsHandler.getCredentialVersionByUUID(id);
  }

  @GetMapping(path = "")
  @ResponseStatus(HttpStatus.OK)
  public DataResponse getCredential(
      @RequestParam(value = "name") String credentialName,
      @RequestParam(value = "versions", required = false) Integer numberOfVersions,
      @RequestParam(value = "current", required = false, defaultValue = "false") boolean current) {
    if (StringUtils.isEmpty(credentialName)) {
      throw new InvalidQueryParameterException("error.missing_query_parameter", "name");
    }

    if (current && numberOfVersions != null) {
      throw new InvalidQueryParameterException("error.cant_use_versions_and_current", "name");
    }

    String credentialNameWithPrependedSlash = StringUtils.prependIfMissing(credentialName, "/");

    auditRecord.setRequestDetails(new GetCredential(credentialName, numberOfVersions, current));

    if (current) {
      return credentialsHandler
          .getCurrentCredentialVersions(credentialNameWithPrependedSlash);
    } else {
      return credentialsHandler
          .getNCredentialVersions(credentialNameWithPrependedSlash, numberOfVersions);
    }
  }

  @RequestMapping(path = "", params = "path", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public FindCredentialResults findByPath(@RequestParam("path") String path) {
    FindCredential findCredential = new FindCredential();
    findCredential.setPath(path);
    auditRecord.setRequestDetails(findCredential);

    return new FindCredentialResults(credentialService.findStartingWithPath(path));
  }

  @RequestMapping(path = "", params = "name-like", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public FindCredentialResults findByNameLike(@RequestParam("name-like") String nameLike) {
    FindCredential findCredential = new FindCredential();
    findCredential.setNameLike(nameLike);
    auditRecord.setRequestDetails(findCredential);

    return new FindCredentialResults(credentialService.findContainingName(nameLike));
  }

  private CredentialView auditedHandlePutRequest(@RequestBody BaseCredentialSetRequest requestBody) {
    auditRecord.setRequestDetails(new SetCredential(requestBody.getName(), requestBody.getType(),
        requestBody.getAdditionalPermissions()));
    return setHandler.handle(requestBody);
  }
}
