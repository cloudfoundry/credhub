package io.pivotal.security.service;

import io.pivotal.security.data.OperationAuditRecordDataService;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.util.InstantFactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import javax.annotation.PostConstruct;

@Service
public class DatabaseAuditLogService implements AuditLogService {

  @Autowired
  InstantFactoryBean instantFactoryBean;

  @Autowired
  ResourceServerTokenServices tokenServices;

  @Autowired
  OperationAuditRecordDataService operationAuditRecordDataService;

  @Autowired
  PlatformTransactionManager transactionManager;

  @Autowired
  MessageSource messageSource;

  @Autowired
  SecurityEventsLogService securityEventsLogService;

  private MessageSourceAccessor messageSourceAccessor;

  @PostConstruct
  public void init() {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @Override
  public ResponseEntity<?> performWithAuditing(String operation, AuditRecordParameters auditRecordParameters, Supplier<ResponseEntity<?>> action) throws
      Exception {
    TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());

    boolean auditSuccess = true;

    ResponseEntity<?> responseEntity = new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    RuntimeException thrown = null;
    try {
      responseEntity = action.get();
      if (!responseEntity.getStatusCode().is2xxSuccessful()) {
        auditSuccess = false;
        transactionManager.rollback(transaction);
        transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
      }
    } catch (RuntimeException e) {
      thrown = e;
      auditSuccess = false;
      transactionManager.rollback(transaction);
      transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
    }

    OperationAuditRecord auditRecord = getOperationAuditRecord(operation, auditRecordParameters, responseEntity.getStatusCodeValue(), auditSuccess);

    try {
      operationAuditRecordDataService.save(auditRecord);
      transactionManager.commit(transaction);
      securityEventsLogService.log(auditRecord);
    } catch (Exception e) {
      if (!transaction.isCompleted()) transactionManager.rollback(transaction);
      final Map<String, String> error = Collections.singletonMap("error", messageSourceAccessor.getMessage("error.audit_save_failure"));
      return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    if (thrown != null) {
      throw thrown;
    }

    return responseEntity;
  }

  private OperationAuditRecord getOperationAuditRecord(String operation, AuditRecordParameters auditRecordParameters, int statusCode, boolean success) throws Exception {
    Authentication authentication = auditRecordParameters.getAuthentication();
    OAuth2Request oAuth2Request = ((OAuth2Authentication) authentication).getOAuth2Request();
    OAuth2AuthenticationDetails authenticationDetails = (OAuth2AuthenticationDetails) authentication.getDetails();
    OAuth2AccessToken accessToken = tokenServices.readAccessToken(authenticationDetails.getTokenValue());
    Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();
    Set<String> scope = oAuth2Request.getScope();
    return new OperationAuditRecord(
        instantFactoryBean.getObject(),
        auditRecordParameters.getCredentialName(),
        operation,
        (String) additionalInformation.get("user_id"),
        (String) additionalInformation.get("user_name"),
        (String) additionalInformation.get("iss"),
        claimValueAsLong(additionalInformation, "iat"),
        accessToken.getExpiration().getTime() / 1000,
        auditRecordParameters.getHostName(),
        auditRecordParameters.getMethod(),
        auditRecordParameters.getPath(),
        auditRecordParameters.getQueryParameters(),
        statusCode,
        auditRecordParameters.getRequesterIp(),
        auditRecordParameters.getXForwardedFor(),
        oAuth2Request.getClientId(),
        scope == null ? "" : String.join(",", scope),
        oAuth2Request.getGrantType(),
        success
    );
  }

  /*
   * The "iat" and "exp" claims are parsed by Jackson as integers. That means we have a
   * Year-2038 bug. In the hope that Jackson will someday be fixed, this function returns
   * a numeric value as long.
   */
  private long claimValueAsLong(Map<String, Object> additionalInformation, String claimName) {
    return ((Number) additionalInformation.get(claimName)).longValue();
  }
}
