package io.pivotal.security.aspect;

import io.pivotal.security.entity.Credential;
import org.apache.commons.lang3.StringUtils;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

@Component
@Aspect
public class CredentialNameAspect {
  @Around(
      "(execution(* io.pivotal.security.repository.CredentialRepository.*ByNameIgnoreCase(String)) && args(name)) " +
          "|| " +
          "(execution(* io.pivotal.security.data.CredentialVersionDataService.findAllCertificateCredentialsByCaName(String)) && args(name))"
  )
  public Object addLeadingSlash(ProceedingJoinPoint joinPoint, String name) throws Throwable {
    name = StringUtils.prependIfMissing(name, "/");
    return joinPoint.proceed(new Object[]{name});
  }

  @Around(
      "execution(* io.pivotal.security.repository.CredentialRepository.save*(..))"
          + "&& args(credential)"
  )
  public Object addLeadingSlash(ProceedingJoinPoint joinPoint, Credential credential) throws Throwable {
    String name = credential.getName();
    name = StringUtils.prependIfMissing(name, "/");
    credential.setName(name);

    return joinPoint.proceed(new Object[]{credential});
  }
}
