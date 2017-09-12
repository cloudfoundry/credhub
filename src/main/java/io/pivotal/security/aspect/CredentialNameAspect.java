package io.pivotal.security.aspect;

import io.pivotal.security.entity.CredentialName;
import org.apache.commons.lang3.StringUtils;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

@Component
@Aspect
public class CredentialNameAspect {
  @Around(
      "(execution(* io.pivotal.security.repository.CredentialNameRepository.*ByNameIgnoreCase(String)) && args(name)) " +
          "|| " +
          "(execution(* io.pivotal.security.data.CredentialDataService.findAllCertificateCredentialsByCaName(String)) && args(name))"
  )
  public Object addLeadingSlash(ProceedingJoinPoint joinPoint, String name) throws Throwable {
    name = StringUtils.prependIfMissing(name, "/");
    return joinPoint.proceed(new Object[]{name});
  }

  @Around(
      "execution(* io.pivotal.security.repository.CredentialNameRepository.save*(..))"
          + "&& args(credentialName)"
  )
  public Object addLeadingSlash(ProceedingJoinPoint joinPoint, CredentialName credentialName) throws Throwable {
    String name = credentialName.getName();
    name = StringUtils.prependIfMissing(name, "/");
    credentialName.setName(name);

    return joinPoint.proceed(new Object[]{credentialName});
  }
}
