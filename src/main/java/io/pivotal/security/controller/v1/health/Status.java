package io.pivotal.security.controller.v1.health;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

/**
 * Value object to express state of a component or subsystem.
 * <p>
 * Status provides convenient constants for commonly used states like {@link #UP},
 * {@link #DOWN} or {@link #OUT_OF_SERVICE}.
 * <p>
 * Custom states can also be created and used throughout the Spring Boot Health subsystem.
 *
 * @author Christian Dupuis
 * @since 1.1.0
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public final class Status {

  /**
   * Convenient constant value representing unknown state.
   */
  public static final Status UNKNOWN = new Status("UNKNOWN");

  /**
   * Convenient constant value representing up state.
   */
  public static final Status UP = new Status("UP");

  /**
   * Convenient constant value representing down state.
   */
  public static final Status DOWN = new Status("DOWN");

  /**
   * Convenient constant value representing out-of-service state.
   */
  public static final Status OUT_OF_SERVICE = new Status("OUT_OF_SERVICE");

  private final String code;

  private final String description;

  /**
   * Create a new {@link Status} instance with the given code and an empty description.
   * @param code the status code
   */
  public Status(String code) {
    this(code, "");
  }

  /**
   * Create a new {@link Status} instance with the given code and description.
   * @param code the status code
   * @param description a description of the status
   */
  public Status(String code, String description) {
    Assert.notNull(code, "Code must not be null");
    Assert.notNull(description, "Description must not be null");
    this.code = code;
    this.description = description;
  }

  /**
   * Return the code for this status.
   * @return the code
   */
  @JsonProperty("status")
  public String getCode() {
    return this.code;
  }

  /**
   * Return the description of this status.
   * @return the description
   */
  @JsonInclude(JsonInclude.Include.NON_EMPTY)
  public String getDescription() {
    return this.description;
  }

  @Override
  public String toString() {
    return this.code;
  }

  @Override
  public int hashCode() {
    return this.code.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (obj != null && obj instanceof Status) {
      return ObjectUtils.nullSafeEquals(this.code, ((Status) obj).code);
    }
    return false;
  }

}
