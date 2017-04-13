package io.pivotal.security.entity;

import io.pivotal.security.util.InstantMillisecondsConverter;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

import static io.pivotal.security.constants.UuidConstants.UUID_BYTES;

@Entity
@Table(name = "EventAuditRecord")
@EntityListeners(AuditingEntityListener.class)
public class EventAuditRecord {
  @Id
  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  @GeneratedValue(generator = "uuid2")
  @GenericGenerator(name = "uuid2", strategy = "uuid2")
  private UUID uuid;

  @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
  private UUID requestUuid;

  @Convert(converter = InstantMillisecondsConverter.class)
  @Column(nullable = false, columnDefinition = "BIGINT NOT NULL")
  @CreatedDate
  private Instant now;

  private String credentialName;
  private String operation;
  private boolean success = true;
  private String actor;

  // for Hibernate
  @SuppressWarnings("unused")
  private EventAuditRecord() { }

  public EventAuditRecord(
      String operation,
      String credentialName,
      String actor,
      UUID requestUuid,
      boolean success
  ) {
    this.operation = operation;
    this.credentialName = credentialName;
    this.actor = actor;
    this.requestUuid = requestUuid;
    this.success = success;
  }

  public UUID getUuid() {
    return uuid;
  }

  public UUID getRequestUuid() {
    return requestUuid;
  }

  public Instant getNow() {
    return now;
  }

  public String getCredentialName() {
    return credentialName;
  }

  public String getOperation() {
    return operation;
  }

  public boolean isSuccess() {
    return success;
  }

  public String getActor() {
    return actor;
  }
}
