package org.cloudfoundry.credhub.credentials;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

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

import com.google.common.io.ByteStreams;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.RequestDetails;
import org.cloudfoundry.credhub.audit.entities.DeleteCredential;
import org.cloudfoundry.credhub.audit.entities.FindCredential;
import org.cloudfoundry.credhub.audit.entities.GetCredential;
import org.cloudfoundry.credhub.audit.entities.SetCredential;
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException;
import org.cloudfoundry.credhub.generate.CredentialsHandler;
import org.cloudfoundry.credhub.generate.LegacyGenerationHandler;
import org.cloudfoundry.credhub.generate.SetHandler;
import org.cloudfoundry.credhub.requests.BaseCredentialSetRequest;
import org.cloudfoundry.credhub.services.PermissionedCredentialService;
import org.cloudfoundry.credhub.views.CredentialView;
import org.cloudfoundry.credhub.views.DataResponse;
import org.cloudfoundry.credhub.views.FindCredentialResults;

@RestController
@RequestMapping(
  path = CredentialsController.ENDPOINT,
  produces = MediaType.APPLICATION_JSON_UTF8_VALUE
)
public class CredentialsController {

  public static final String ENDPOINT = "/api/v1/data";

  private final PermissionedCredentialService permissionedCredentialService;
  private final SetHandler setHandler;
  private final CredentialsHandler credentialsHandler;
  private final LegacyGenerationHandler legacyGenerationHandler;
  private final CEFAuditRecord auditRecord;

  @Autowired
  public CredentialsController(
    final PermissionedCredentialService permissionedCredentialService,
    final CredentialsHandler credentialsHandler,
    final SetHandler setHandler,
    final LegacyGenerationHandler legacyGenerationHandler,
    final CEFAuditRecord auditRecord
  ) {
    super();
    this.permissionedCredentialService = permissionedCredentialService;
    this.credentialsHandler = credentialsHandler;
    this.setHandler = setHandler;
    this.legacyGenerationHandler = legacyGenerationHandler;
    this.auditRecord = auditRecord;
  }

  @RequestMapping(path = "", method = RequestMethod.POST)
  @ResponseStatus(HttpStatus.OK)
  public synchronized CredentialView generate(final InputStream inputStream) throws IOException {
    final InputStream requestInputStream = new ByteArrayInputStream(ByteStreams.toByteArray(inputStream));
    return legacyGenerationHandler.auditedHandlePostRequest(requestInputStream);
  }

  @RequestMapping(path = "", method = RequestMethod.PUT)
  @ResponseStatus(HttpStatus.OK)
  public synchronized CredentialView set(@RequestBody final BaseCredentialSetRequest requestBody) {
    requestBody.validate();
    return auditedHandlePutRequest(requestBody);
  }

  @RequestMapping(path = "", method = RequestMethod.DELETE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void delete(@RequestParam("name") final String credentialName) {
    if (StringUtils.isEmpty(credentialName)) {
      throw new InvalidQueryParameterException(ErrorMessages.MISSING_QUERY_PARAMETER, "name");
    }

    final String credentialNameWithPrependedSlash = StringUtils.prependIfMissing(credentialName, "/");

    final RequestDetails requestDetails = new DeleteCredential(credentialNameWithPrependedSlash);
    auditRecord.setRequestDetails(requestDetails);

    credentialsHandler.deleteCredential(credentialNameWithPrependedSlash);
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView findById(@PathVariable final String id) {
    return credentialsHandler.getCredentialVersionByUUID(id);
  }

  @GetMapping(path = "")
  @ResponseStatus(HttpStatus.OK)
  public DataResponse getByName(
    @RequestParam("name") final String credentialName,
    @RequestParam(value = "versions", required = false) final Integer numberOfVersions,
    @RequestParam(value = "current", required = false, defaultValue = "false") final boolean current
  ) {
    if (StringUtils.isEmpty(credentialName)) {
      throw new InvalidQueryParameterException(ErrorMessages.MISSING_QUERY_PARAMETER, "name");
    }

    if (current && numberOfVersions != null) {
      throw new InvalidQueryParameterException(ErrorMessages.CANT_USE_VERSIONS_AND_CURRENT, "name");
    }

    final String credentialNameWithPrependedSlash = StringUtils.prependIfMissing(credentialName, "/");

    auditRecord.setRequestDetails(new GetCredential(credentialName, numberOfVersions, current));

    if (current) {
      return credentialsHandler.getCurrentCredentialVersions(credentialNameWithPrependedSlash);
    } else {
      return credentialsHandler.getNCredentialVersions(credentialNameWithPrependedSlash, numberOfVersions);
    }
  }

  @RequestMapping(path = "", params = "path", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public FindCredentialResults findByPath(
    @RequestParam("path") final String path,
    @RequestParam(value = "expires-within-days", required = false, defaultValue = "") final String expiresWithinDays
  ) {
    final FindCredential findCredential = new FindCredential();
    findCredential.setPath(path);
    findCredential.setExpiresWithinDays(expiresWithinDays);
    auditRecord.setRequestDetails(findCredential);

    return new FindCredentialResults(permissionedCredentialService.findStartingWithPath(path, expiresWithinDays));
  }

  @RequestMapping(path = "", params = "name-like", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public FindCredentialResults findByNameLike(
    @RequestParam("name-like") final String nameLike,
    @RequestParam(value = "expires-within-days", required = false, defaultValue = "") final String expiresWithinDays
  ) {
    final FindCredential findCredential = new FindCredential();
    findCredential.setNameLike(nameLike);
    findCredential.setExpiresWithinDays(expiresWithinDays);
    auditRecord.setRequestDetails(findCredential);

    return new FindCredentialResults(permissionedCredentialService.findContainingName(nameLike, expiresWithinDays));
  }

  private CredentialView auditedHandlePutRequest(@RequestBody final BaseCredentialSetRequest requestBody) {
    auditRecord.setRequestDetails(new SetCredential(requestBody.getName(), requestBody.getType()));
    return setHandler.handle(requestBody);
  }
}
