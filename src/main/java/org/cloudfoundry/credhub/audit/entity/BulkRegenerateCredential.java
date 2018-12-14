package org.cloudfoundry.credhub.audit.entity;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.cloudfoundry.credhub.audit.OperationDeviceAction;

public class BulkRegenerateCredential implements RequestDetails {
  private String signedBy;

  public BulkRegenerateCredential() {
    super();

  }

  public BulkRegenerateCredential(final String signedBy) {
    super();
    this.signedBy = signedBy;
  }


  public String getSignedBy() {
    return signedBy;
  }

  public void setSignedBy(final String signedBy) {
    this.signedBy = signedBy;
  }

  @Override
  public OperationDeviceAction operation() {
    return OperationDeviceAction.BULK_REGENERATE;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    final BulkRegenerateCredential that = (BulkRegenerateCredential) o;

    return new EqualsBuilder()
      .append(signedBy, that.signedBy)
      .isEquals();
  }

  @Override
  public int hashCode() {
    return new HashCodeBuilder(17, 37)
      .append(signedBy)
      .toHashCode();
  }
}
