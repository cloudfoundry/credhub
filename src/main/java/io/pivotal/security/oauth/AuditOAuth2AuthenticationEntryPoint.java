package io.pivotal.security.oauth;

import io.pivotal.security.entity.AuthFailureAuditRecord;
import io.pivotal.security.repository.AuthFailureAuditRecordRepository;
import io.pivotal.security.service.AuditRecordParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.stereotype.Service;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Service
public class AuditOAuth2AuthenticationEntryPoint extends OAuth2AuthenticationEntryPoint {

  @Autowired
  AuthFailureAuditRecordRepository auditRecordRepository;

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
      throws IOException, ServletException {
    logAuthFailureToDb(authException, new AuditRecordParameters(request), request.getMethod());
    doHandle(request, response, authException);
  }

  private void logAuthFailureToDb(AuthenticationException authException, AuditRecordParameters parameters, String requestMethod) {
    RequestToOperationTranslator requestToOperationTranslator = new RequestToOperationTranslator(parameters.getPath()).setMethod(requestMethod);
    AuthFailureAuditRecord authFailureAuditRecord = new AuthFailureAuditRecord()
        .setNow(0) //fixme
        .setOperation(requestToOperationTranslator.translate())
        .setFailureReason(parseFailureReason(authException))
        .setFailureDescription(authException.getMessage())
        .setUserId(null) //fixme
        .setUserName(null) //fixme
        .setUaaUrl(null) //fixme
        .setTokenIssued(-1) //fixme
        .setTokenExpires(-1) //fixme
        .setHostName(parameters.getHostName())
        .setPath(parameters.getPath())
        .setRequesterIp(parameters.getRequesterIp())
        .setXForwardedFor(parameters.getXForwardedFor());
    auditRecordRepository.save(authFailureAuditRecord);
  }

  private String parseFailureReason(AuthenticationException authException) {
    return authException.getCause().toString().split("\"")[1];
  }
}


