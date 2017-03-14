package io.pivotal.security.validator;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Target({ TYPE, ANNOTATION_TYPE })
@Retention(RUNTIME)
@Constraint(validatedBy = { ValidRegenerateRequestValidator.class })
public @interface ValidRegenerateRequest {
  String message();
  Class<? extends Payload>[] payload() default { };
  Class<?>[] groups() default { };
}
