package io.pivotal.security.controller.v1.secret;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.ByteStreams;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.controller.v1.SecretKindMappingFactory;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.entity.AuditingOperationCode;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseSecretGenerateRequest;
import io.pivotal.security.request.BaseSecretSetRequest;
import io.pivotal.security.request.DefaultSecretGenerateRequest;
import io.pivotal.security.request.SecretRegenerateRequest;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.service.SetService;
import io.pivotal.security.util.CheckedFunction;
import io.pivotal.security.view.DataResponse;
import io.pivotal.security.view.FindCredentialResults;
import io.pivotal.security.view.FindPathResults;
import io.pivotal.security.view.SecretKind;
import io.pivotal.security.view.SecretKindFromString;
import io.pivotal.security.view.SecretView;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.util.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.orm.jpa.JpaSystemException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_FIND;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping(
    path = SecretsController.API_V1_DATA,
    produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

  public static final String API_V1_DATA = "/api/v1/data";

  private static final Logger LOGGER = LogManager.getLogger(SecretsController.class);
  private final SecretDataService secretDataService;
  private final NamedSecretGenerateHandler namedSecretGenerateHandler;
  private final JsonContextFactory jsonContextFactory;
  private final AuditLogService auditLogService;
  private final ObjectMapper objectMapper;
  private final GenerateService generateService;
  private final SetService setService;
  private final RegenerateService regenerateService;

  @Autowired
  public SecretsController(SecretDataService secretDataService,
                           NamedSecretGenerateHandler namedSecretGenerateHandler,
                           JsonContextFactory jsonContextFactory,
                           AuditLogService auditLogService,
                           ObjectMapper objectMapper,
                           GenerateService generateService,
                           SetService setService,
                           RegenerateService regenerateService
  ) {
    this.secretDataService = secretDataService;
    this.namedSecretGenerateHandler = namedSecretGenerateHandler;
    this.jsonContextFactory = jsonContextFactory;
    this.auditLogService = auditLogService;
    this.objectMapper = objectMapper;
    this.generateService = generateService;
    this.setService = setService;
    this.regenerateService = regenerateService;
  }

  @RequestMapping(path = "", method = RequestMethod.POST)
  public ResponseEntity generate(InputStream inputStream,
      HttpServletRequest request,
      UserContext userContext,
      AccessControlEntry currentUserAccessControlEntry) throws Exception {
    InputStream requestInputStream = new ByteArrayInputStream(ByteStreams.toByteArray(inputStream));
    try {
      return auditedHandlePostRequest(requestInputStream, request, userContext, currentUserAccessControlEntry);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      requestInputStream.reset();
      LOGGER.error(
          "Exception \"" + e.getMessage() + "\" with class \"" + e.getClass().getCanonicalName()
              + "\" while storing secret, possibly caused by race condition, retrying...");
      return auditedHandlePostRequest(requestInputStream, request, userContext, currentUserAccessControlEntry);
    }
  }

  @RequestMapping(path = "", method = RequestMethod.PUT)
  public ResponseEntity set(@RequestBody BaseSecretSetRequest requestBody,
      HttpServletRequest request,
      UserContext userContext,
      AccessControlEntry currentUserAccessControlEntry) throws Exception {
    requestBody.validate();

    requestBody.addCurrentUser(currentUserAccessControlEntry);
    try {
      return auditedHandlePutRequest(requestBody, request, userContext);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      LOGGER.error(
          "Exception \"" + e.getMessage() + "\" with class \"" + e.getClass().getCanonicalName()
              + "\" while storing secret, possibly caused by race condition, retrying...");
      return auditedHandlePutRequest(requestBody, request, userContext);
    }
  }

  @RequestMapping(path = "", method = RequestMethod.DELETE)
  public ResponseEntity delete(
      @RequestParam(value = "name") String secretName,
      HttpServletRequest request,
      UserContext userContext
  ) throws Exception {
    if (StringUtils.isEmpty(secretName)) {
      throw new MissingServletRequestParameterException("name", "String");
    }

    return auditLogService.performWithAuditing(auditRecorder -> {
      auditRecorder.setCredentialName(secretName);
      auditRecorder.populateFromRequest(request);
      auditRecorder.setUserContext(userContext);

      if (!secretDataService.delete(secretName)) {
        throw new EntryNotFoundException("error.credential_not_found");
      }

      return new ResponseEntity(HttpStatus.NO_CONTENT);
    });
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.GET)
  public ResponseEntity getSecretById(
      @PathVariable String id,
      HttpServletRequest request,
      UserContext userContext) throws Exception {

    return retrieveSecretWithAuditing(
        id,
        findAsList(secretDataService::findByUuid),
        request,
        userContext,
        true
    );
  }

  @RequestMapping(path = "", method = RequestMethod.GET)
  public ResponseEntity getSecret(
      @RequestParam(value = "name", required = false) String secretName,
      @RequestParam(value = "current", required = false, defaultValue = "false") boolean current,
      HttpServletRequest request,
      UserContext userContext) throws Exception {

    return retrieveSecretWithAuditing(
        secretName,
        selectLookupFunction(current),
        request,
        userContext,
        false
    );
  }

  @RequestMapping(path = "", params = "path", method = RequestMethod.GET)
  public ResponseEntity findByPath(
      @RequestParam Map<String, String> params,
      HttpServletRequest request,
      UserContext userContext
  ) throws Exception {
    return findStartingWithAuditing(params.get("path"), request, userContext);
  }

  @RequestMapping(path = "", params = "paths=true", method = RequestMethod.GET)
  public ResponseEntity findPaths(HttpServletRequest request, UserContext userContext)
      throws Exception {
    return findPathsWithAuditing(request, userContext);
  }

  @RequestMapping(path = "", params = "name-like", method = RequestMethod.GET)
  public ResponseEntity findByNameLike(
      @RequestParam Map<String, String> params,
      HttpServletRequest request,
      UserContext userContext
  ) throws Exception {
    return findWithAuditing(params.get("name-like"), secretDataService::findContainingName, request,
        userContext);
  }

  private ResponseEntity auditedHandlePostRequest(
      InputStream inputStream,
      HttpServletRequest request,
      UserContext userContext,
      AccessControlEntry currentUserAccessControlEntry
  ) throws Exception {
    return auditLogService.performWithAuditing((auditRecordBuilder -> {
      return deserializeAndHandlePostRequest(
          inputStream,
          request,
          userContext,
          auditRecordBuilder,
          currentUserAccessControlEntry);
    }));
  }

  private ResponseEntity<?> deserializeAndHandlePostRequest(
      InputStream inputStream,
      HttpServletRequest request,
      UserContext userContext,
      AuditRecordBuilder auditRecordBuilder,
      AccessControlEntry currentUserAccessControlEntry
  ) throws IOException {
    String requestString = IOUtils.toString(new InputStreamReader(inputStream));
    boolean isRegenerateRequest = readRegenerateFlagFrom(requestString);

    auditRecordBuilder.populateFromRequest(request);
    auditRecordBuilder.setUserContext(userContext);
    if (isRegenerateRequest) {
      // If it's a regenerate request deserialization is simple; the generation case requires
      // polymorphic deserialization See BaseSecretGenerateRequest to see how that's done. It
      // would be nice if Jackson could pick a subclass based on an arbitrary function, since
      // we want to consider both type and .regenerate. We could do custom deserialization but
      // then we'd have to do the entire job by hand.
      return handleRegenerateRequest(auditRecordBuilder, inputStream, requestString);
    } else {
      return handleGenerateRequest(auditRecordBuilder, inputStream, requestString,currentUserAccessControlEntry);
    }
  }

  private ResponseEntity handleGenerateRequest(
      AuditRecordBuilder auditRecordBuilder,
      InputStream requestInputStream,
      String requestString,
      AccessControlEntry currentUserAccessControlEntry
  ) throws IOException {
    BaseSecretGenerateRequest requestBody = objectMapper.readValue(requestString, BaseSecretGenerateRequest.class);
    requestBody.validate();
    requestBody.addCurrentUser(currentUserAccessControlEntry);

    auditRecordBuilder.setCredentialName(requestBody.getName());
    final boolean isCurrentlyTrappedInTheMonad = requestBody instanceof DefaultSecretGenerateRequest;
    if (isCurrentlyTrappedInTheMonad) {
      requestInputStream.reset();
      DocumentContext parsedRequestBody = jsonContextFactory.getParseContext().parse(requestInputStream);
      return storeSecret(auditRecordBuilder, namedSecretGenerateHandler, parsedRequestBody);
    } else {
      return generateService.performGenerate(auditRecordBuilder, requestBody);
    }
  }

  private ResponseEntity handleRegenerateRequest(
      AuditRecordBuilder auditRecordBuilder,
      InputStream requestInputStream,
      String requestString
  ) throws IOException {
    SecretRegenerateRequest requestBody = objectMapper.readValue(requestString, SecretRegenerateRequest.class);

    ResponseEntity responseEntity = regenerateService.performRegenerate(auditRecordBuilder, requestBody);

    boolean isCurrentlyTrappedInTheMonad = responseEntity == null;
    if (isCurrentlyTrappedInTheMonad) {
      requestInputStream.reset();
      DocumentContext parsedRequestBody = jsonContextFactory.getParseContext().parse(requestInputStream);
      return storeSecret(auditRecordBuilder, namedSecretGenerateHandler, parsedRequestBody);
    } else {
      return responseEntity;
    }
  }

  private ResponseEntity auditedHandlePutRequest(
      @RequestBody BaseSecretSetRequest requestBody,
      HttpServletRequest request,
      UserContext userContext
  ) throws Exception {
    return auditLogService.performWithAuditing(auditRecordBuilder -> {
      return handlePutRequest(requestBody, request, userContext, auditRecordBuilder);
    });
  }

  private ResponseEntity<?> handlePutRequest(
      @RequestBody BaseSecretSetRequest requestBody,
      HttpServletRequest request,
      UserContext userContext,
      AuditRecordBuilder auditRecordBuilder
  ) throws Exception {
    auditRecordBuilder.setCredentialName(requestBody.getName());
    auditRecordBuilder.populateFromRequest(request);
    auditRecordBuilder.setUserContext(userContext);

    return setService.performSet(auditRecordBuilder, requestBody);
  }

  private Function<String, List<NamedSecret>> selectLookupFunction(boolean current) {
    if (current) {
      return findAsList(secretDataService::findMostRecent);
    } else {
      return secretDataService::findAllByName;
    }
  }

  private Function<String, List<NamedSecret>> findAsList(Function<String, NamedSecret> finder) {
    return (toFind) -> {
      NamedSecret namedSecret = finder.apply(toFind);
      return namedSecret != null ? newArrayList(namedSecret) : newArrayList();
    };
  }

  private ResponseEntity retrieveSecretWithAuditing(String identifier,
      Function<String, List<NamedSecret>> finder,
      HttpServletRequest request,
      UserContext userContext,
      boolean returnFirstEntry) throws Exception {
    return auditLogService.performWithAuditing(auditRecordBuilder -> {
      auditRecordBuilder.populateFromRequest(request);
      auditRecordBuilder.setUserContext(userContext);

      if (StringUtils.isEmpty(identifier)) {
        throw new MissingServletRequestParameterException("name", "String");
      }
      List<NamedSecret> namedSecrets = finder.apply(identifier);
      if (namedSecrets.isEmpty()) {
        throw new EntryNotFoundException("error.credential_not_found");
      } else {
        ResponseEntity success;
        auditRecordBuilder.setCredentialName(namedSecrets.get(0).getName());
        try {
          if (returnFirstEntry) {
            success = new ResponseEntity<>(SecretView.fromEntity(namedSecrets.get(0)),
                HttpStatus.OK);
          } else {
            success = new ResponseEntity<>(DataResponse.fromEntity(namedSecrets), HttpStatus.OK);
          }
        } catch (NoSuchAlgorithmException e) {
          throw new RuntimeException(e);
        }
        return success;
      }
    });
  }

  private boolean readRegenerateFlagFrom(String requestString) {
    boolean isRegenerateRequest;
    try {
      isRegenerateRequest = JsonPath.read(requestString, "$.regenerate");
    } catch (PathNotFoundException e) {
      // could have just returned null, that would have been pretty useful
      isRegenerateRequest = false;
    }
    return isRegenerateRequest;
  }

  private ResponseEntity findWithAuditing(String nameSubstring,
      Function<String, List<SecretView>> finder,
      HttpServletRequest request,
      UserContext userContext) throws Exception {
    return auditLogService.performWithAuditing(auditParams -> {
      auditParams.populateFromRequest(request);
      auditParams.setUserContext(userContext);
      auditParams.setOperationCode(CREDENTIAL_FIND);
      List<SecretView> secretViews = finder.apply(nameSubstring);
      return new ResponseEntity<>(FindCredentialResults.fromSecrets(secretViews), HttpStatus.OK);
    });
  }

  private ResponseEntity findPathsWithAuditing(
      HttpServletRequest request,
      UserContext userContext
  ) throws Exception {
    return auditLogService.performWithAuditing(auditParams -> {
      auditParams.populateFromRequest(request);
      auditParams.setUserContext(userContext);
      auditParams.setOperationCode(CREDENTIAL_FIND);
      List<String> paths = secretDataService.findAllPaths();
      return new ResponseEntity<>(FindPathResults.fromEntity(paths), HttpStatus.OK);
    });
  }

  private ResponseEntity<?> storeSecret(
      AuditRecordBuilder auditRecordBuilder,
      SecretKindMappingFactory handler,
      DocumentContext parsedRequestBody
  ) {
    final String secretName = getSecretName(parsedRequestBody);
    if (StringUtils.isEmpty(secretName)) {
      throw new ParameterizedValidationException("error.missing_name");
    }
    NamedSecret existingNamedSecret = secretDataService.findMostRecent(secretName);

    boolean willBeCreated = existingNamedSecret == null;
    boolean overwrite = BooleanUtils.isTrue(parsedRequestBody.read("$.overwrite", Boolean.class));
    boolean regenerate = BooleanUtils.isTrue(parsedRequestBody.read("$.regenerate", Boolean.class));

    boolean willWrite = willBeCreated || overwrite || regenerate;
    AuditingOperationCode operationCode = willWrite ? CREDENTIAL_UPDATE : CREDENTIAL_ACCESS;
    auditRecordBuilder.setOperationCode(operationCode);
    if (regenerate && existingNamedSecret == null) {
      throw new EntryNotFoundException("error.credential_not_found");
    }

    String secretPath = secretName;
    try {
      String requestedSecretType = parsedRequestBody.read("$.type");
      final SecretKind secretKind = (existingNamedSecret != null
          ? existingNamedSecret.getKind()
          : SecretKindFromString.fromString(requestedSecretType));
      if (existingNamedSecret != null && requestedSecretType != null && !existingNamedSecret
          .getSecretType().equals(requestedSecretType)) {
        throw new ParameterizedValidationException("error.type_mismatch");
      }
      secretPath = existingNamedSecret == null ? secretPath : existingNamedSecret.getName();

      NamedSecret storedNamedSecret;
      if (willWrite) {
        SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException> make =
            handler.make(secretPath, parsedRequestBody);
        CheckedFunction<NamedSecret, NoSuchAlgorithmException> lift = secretKind.lift(make);
        storedNamedSecret = lift.apply(existingNamedSecret);
        storedNamedSecret = secretDataService.save(storedNamedSecret);
      } else {
        // To catch invalid parameters, validate request even though we throw away the result.
        // We need to apply it to null or Hibernate may decide to save the record.
        // As above, the unit tests won't catch (all) issues :( ,
        // but there is an integration test to cover it.
        storedNamedSecret = existingNamedSecret;
        secretKind.lift(handler.make(secretPath, parsedRequestBody)).apply(null);
      }

      SecretView secretView = SecretView.fromEntity(storedNamedSecret);
      return new ResponseEntity<>(secretView, HttpStatus.OK);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private String getSecretName(DocumentContext parsed) {
    return parsed.read("$.name", String.class);
  }

  private ResponseEntity findStartingWithAuditing(String path, HttpServletRequest request,
      UserContext userContext) throws Exception {
    return findWithAuditing(path, secretDataService::findStartingWithPath, request, userContext);
  }
}
