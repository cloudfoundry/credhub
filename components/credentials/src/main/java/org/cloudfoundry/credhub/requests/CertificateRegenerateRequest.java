package org.cloudfoundry.credhub.requests;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

@JsonAutoDetect
@SuppressWarnings("unused")
public class CertificateRegenerateRequest {

  @JsonProperty("set_as_transitional")
  private boolean transitional;

  public CertificateRegenerateRequest() {
    super();
    /* this needs to be there for jackson to be happy */
  }

  public CertificateRegenerateRequest(final boolean transitional) {
    super();
    this.transitional = transitional;
  }

  public boolean isTransitional() {
    return transitional;
  }

  @JsonProperty("set_as_transitional")
  public void setTransitional(final boolean transitional) {
    this.transitional = transitional;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    final CertificateRegenerateRequest that = (CertificateRegenerateRequest) o;

    return new EqualsBuilder()
      .append(transitional, that.transitional)
      .isEquals();
  }

  @Override
  public int hashCode() {
    return new HashCodeBuilder(17, 37)
      .append(transitional)
      .toHashCode();
  }
}
