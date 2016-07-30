package io.pivotal.security.interceptor;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.repository.AuditRecordRepository;
import io.pivotal.security.util.CurrentTimeProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.ZoneOffset;
import java.util.*;

@Component
public class DatabaseAuditLogInterceptor extends HandlerInterceptorAdapter implements AuditLogInterceptor {

  public static final String TX_KEY = DatabaseAuditLogInterceptor.class.getName() + "tx";

  @Autowired
  PlatformTransactionManager transactionManager;

  @Autowired
  AuditRecordRepository auditRecordRepository;

  @Autowired
  CurrentTimeProvider currentTimeProvider;

  @Autowired
  ResourceServerTokenServices tokenServices;

  @Autowired
  ObjectMapper serializingObjectMapper;

  @Autowired
  OperationNameResolver operationNameResolver;

  @Autowired
  MessageSource messageSource;

  private MessageSourceAccessor messageSourceAccessor;

  @PostConstruct
  public void init() {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
    TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
    request.setAttribute(TX_KEY, transaction);
    return true;
  }

  @Override
  public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
    TransactionStatus transactionStatus = (TransactionStatus) request.getAttribute(TX_KEY);
    OperationAuditRecord auditRecord = getOperationAuditRecord(request, handler);
    if (ex != null || !is2XX(response.getStatus())) {
      auditRecord.setFailed();
      transactionManager.rollback(transactionStatus);
      transactionStatus = transactionManager.getTransaction(new DefaultTransactionDefinition());
    }

    try {
      auditRecordRepository.save(auditRecord);
      transactionManager.commit(transactionStatus);
    } catch (Exception e) {
      transactionManager.rollback(transactionStatus);
      response.reset();
      response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      serializingObjectMapper.writeValue(response.getOutputStream(), Collections.singletonMap("error", messageSourceAccessor.getMessage("error.audit_save_failure")));
    }
    super.afterCompletion(request, response, handler, ex);
  }

  private boolean is2XX(int status) {
    return status >= 200 && status < 300;
  }

  private OperationAuditRecord getOperationAuditRecord(HttpServletRequest request, Object handler) {
    OAuth2AuthenticationDetails authenticationDetails = (OAuth2AuthenticationDetails) SecurityContextHolder.getContext().getAuthentication().getDetails();
    OAuth2AccessToken accessToken = tokenServices.readAccessToken(authenticationDetails.getTokenValue());
    Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();
    return new OperationAuditRecord(
        currentTimeProvider.getCurrentTime().toInstant(ZoneOffset.UTC).toEpochMilli(),
        operationNameResolver.getOperationFromMethod(handler),
        (String) additionalInformation.get("user_id"),
        (String) additionalInformation.get("user_name"),
        (String) additionalInformation.get("iss"),
        claimValueAsLong(additionalInformation, "iat"),
        accessToken.getExpiration().getTime() / 1000,
        request.getServerName(),
        request.getRequestURI()
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
