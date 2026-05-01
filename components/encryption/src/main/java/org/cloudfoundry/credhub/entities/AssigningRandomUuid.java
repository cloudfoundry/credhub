package org.cloudfoundry.credhub.entities;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.hibernate.annotations.IdGeneratorType;

/**
 * Hibernate 7+ id generator: random UUID on insert, or keep an identifier already set on the entity.
 */
@IdGeneratorType(AssigningRandomUuidGenerator.class)
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.FIELD, ElementType.METHOD })
public @interface AssigningRandomUuid {
}
