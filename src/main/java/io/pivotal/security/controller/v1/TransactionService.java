package io.pivotal.security.controller.v1;

import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.repository.InMemoryAuditRecordRepository;
import io.pivotal.security.util.CurrentTimeProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import javax.servlet.http.HttpServletRequest;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.function.Supplier;

@Service
class TransactionService {

  @Autowired
  InMemoryAuditRecordRepository auditRepository;

  @Autowired
  ResourceServerTokenServices tokenServices;

  @Autowired
  CurrentTimeProvider currentTimeProvider;

  @Autowired
  PlatformTransactionManager transactionManager;

  ResponseEntity performWithLogging(String operation, HttpServletRequest httpServletRequest, Supplier<ResponseEntity> controllerBehavior) {
    TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
    OperationAuditRecord auditRecord = getOperationAuditRecord(operation, httpServletRequest);
    try {
      ResponseEntity responseEntity;
      try {
        responseEntity = controllerBehavior.get();
        if (!responseEntity.getStatusCode().is2xxSuccessful()) {
          auditRecord.setFailed();
        }
      } catch (Exception e) {
        auditRecord.setFailed();
        responseEntity = new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
      }
      if (!auditRecord.isSuccess()) {
        transactionManager.rollback(transaction);
        transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
      }
      auditRepository.save(auditRecord);
      transactionManager.commit(transaction);
      return responseEntity;
    } catch (Exception e) {
      transactionManager.rollback(transaction);
      return new ResponseEntity<>("Dan's error message", HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  private OperationAuditRecord getOperationAuditRecord(String operation, HttpServletRequest request) {
    OAuth2AuthenticationDetails authenticationDetails = (OAuth2AuthenticationDetails) SecurityContextHolder.getContext().getAuthentication().getDetails();
    OAuth2AccessToken accessToken = tokenServices.readAccessToken(authenticationDetails.getTokenValue());
    Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();
    return new OperationAuditRecord(
        currentTimeProvider.getCurrentTime().toInstant(ZoneOffset.UTC).toEpochMilli(),
        operation, // todo factory translation
        (String) additionalInformation.get("user_id"),
        (String) additionalInformation.get("user_name"),
        (String) additionalInformation.get("iss"),
        claimValueAsLong(additionalInformation, "iat"),
        accessToken.getExpiration().getTime() / 1000,
        request.getServerName(),
        request.getPathInfo() // include item name per PM
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
