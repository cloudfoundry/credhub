package org.cloudfoundry.credhub.entities;

import java.lang.reflect.Member;
import java.util.EnumSet;
import java.util.UUID;

import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.generator.BeforeExecutionGenerator;
import org.hibernate.generator.EventType;
import org.hibernate.generator.EventTypeSets;
import org.hibernate.generator.GeneratorCreationContext;

/**
 * Replaces the legacy {@code GenericGenerator} + {@code org.hibernate.id.UUIDGenerator} subclass pattern:
 * generates a random UUID when the id is unset, and preserves a caller-assigned UUID.
 */
public class AssigningRandomUuidGenerator implements BeforeExecutionGenerator {

  public AssigningRandomUuidGenerator(
      final AssigningRandomUuid annotation,
      final Member member,
      final GeneratorCreationContext creationContext) {
  }

  @Override
  public EnumSet<EventType> getEventTypes() {
    return EventTypeSets.INSERT_ONLY;
  }

  @Override
  public boolean allowAssignedIdentifiers() {
    return true;
  }

  @Override
  public Object generate(
      final SharedSessionContractImplementor session,
      final Object owner,
      final Object currentValue,
      final EventType eventType) {
    if (currentValue != null) {
      return currentValue;
    }
    return UUID.randomUUID();
  }
}
