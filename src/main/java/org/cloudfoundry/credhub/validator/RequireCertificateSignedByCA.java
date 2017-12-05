package org.cloudfoundry.credhub.validator;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import javax.validation.Constraint;
import javax.validation.Payload;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Target({TYPE, ANNOTATION_TYPE})
@Retention(RUNTIME)
@Constraint(validatedBy = {CertificateSignedByCAValidator.class})
public @interface RequireCertificateSignedByCA {

  String message();

  String[] fields();
  Class<? extends Payload>[] payload() default {};

  Class<?>[] groups() default {};
}
