package io.pivotal.security.service;

import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.repository.AuditRecordRepository;
import io.pivotal.security.util.InstantFactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.util.Collections;
import java.util.Map;
import java.util.function.Supplier;

import javax.annotation.PostConstruct;

@Service
public class DatabaseAuditLogService implements AuditLogService {

  @Autowired
  InstantFactoryBean instantFactoryBean;

  @Autowired
  ResourceServerTokenServices tokenServices;

  @Autowired
  AuditRecordRepository auditRecordRepository;

  @Autowired
  PlatformTransactionManager transactionManager;

  @Autowired
  MessageSource messageSource;

  private MessageSourceAccessor messageSourceAccessor;

  @PostConstruct
  public void init() {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @Override
  public ResponseEntity<?> performWithAuditing(String operation, AuditRecordParameters auditRecordParameters, Supplier<ResponseEntity<?>> action) throws Exception {
    TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());

    OperationAuditRecord auditRecord = getOperationAuditRecord(operation, auditRecordParameters);

    ResponseEntity<?> responseEntity;
    try {
      responseEntity = action.get();
      if (!responseEntity.getStatusCode().is2xxSuccessful()) {
        auditRecord.setFailed();
        transactionManager.rollback(transaction);
        transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
      }
    } catch (RuntimeException e) {
      responseEntity = new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
      auditRecord.setFailed();
      transactionManager.rollback(transaction);
      transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
    }

    try {
      auditRecordRepository.save(auditRecord);
      transactionManager.commit(transaction);
    } catch (Exception e) {
      if (!transaction.isCompleted()) transactionManager.rollback(transaction);
      final Map<String, String> error = Collections.singletonMap("error", messageSourceAccessor.getMessage("error.audit_save_failure"));
      responseEntity = new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    return responseEntity;
  }

  private OperationAuditRecord getOperationAuditRecord(String operation, AuditRecordParameters auditRecordParameters) throws Exception {
    OAuth2AuthenticationDetails authenticationDetails = (OAuth2AuthenticationDetails) auditRecordParameters.getAuthentication().getDetails();
    OAuth2AccessToken accessToken = tokenServices.readAccessToken(authenticationDetails.getTokenValue());
    Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();
    return new OperationAuditRecord(
        instantFactoryBean.getObject().toEpochMilli(),
        operation,
        (String) additionalInformation.get("user_id"),
        (String) additionalInformation.get("user_name"),
        (String) additionalInformation.get("iss"),
        claimValueAsLong(additionalInformation, "iat"),
        accessToken.getExpiration().getTime() / 1000,
        auditRecordParameters.getHostName(),
        auditRecordParameters.getPath(),
        auditRecordParameters.getRequesterIp(),
        auditRecordParameters.getXForwardedFor()
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
