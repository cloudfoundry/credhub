package org.cloudfoundry.credhub.validator;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import javax.validation.Constraint;
import javax.validation.Payload;

@Target({TYPE, ANNOTATION_TYPE})
@Retention(RUNTIME)
@Constraint(validatedBy = {RequireAnyOfValidator.class})
public @interface RequireAnyOf {

  String message();

  String[] fields();

  Class<? extends Payload>[] payload() default {};

  Class<?>[] groups() default {};
}
