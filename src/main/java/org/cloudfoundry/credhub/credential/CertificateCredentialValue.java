package org.cloudfoundry.credhub.credential;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.util.CertificateReader;
import org.cloudfoundry.credhub.util.EmptyStringToNull;
import org.cloudfoundry.credhub.validator.MutuallyExclusive;
import org.cloudfoundry.credhub.validator.RequireAnyOf;
import org.cloudfoundry.credhub.validator.RequireCertificateMatchesPrivateKey;
import org.cloudfoundry.credhub.validator.RequireCertificateSignedByCA;
import org.cloudfoundry.credhub.validator.RequireValidCA;
import org.cloudfoundry.credhub.validator.RequireValidCertificate;
import org.cloudfoundry.credhub.validator.ValidCertificateLength;

@RequireAnyOf(message = "error.missing_certificate_credentials", fields = {"ca", "certificate", "privateKey", })
@MutuallyExclusive(message = "error.mixed_ca_name_and_ca", fields = {"ca", "caName", })
@ValidCertificateLength(message = "error.invalid_certificate_length", fields = {"certificate", "ca", })
@RequireValidCertificate(message = "error.invalid_certificate_value", fields = {"certificate", })
@RequireCertificateSignedByCA(message = "error.certificate_was_not_signed_by_ca", fields = {"ca", })
@RequireCertificateMatchesPrivateKey(message = "error.mismatched_certificate_and_private_key", fields = {"certificate", "privateKey", })
@RequireValidCA(message = "error.invalid_ca_value", fields = {"ca", })
public class CertificateCredentialValue implements CredentialValue {

  @JsonDeserialize(using = EmptyStringToNull.class)
  private String ca;
  @JsonDeserialize(using = EmptyStringToNull.class)
  private String certificate;
  @JsonDeserialize(using = EmptyStringToNull.class)
  private String privateKey;
  @JsonDeserialize(using = EmptyStringToNull.class)
  @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
  private String caName;

  private boolean transitional;

  @SuppressWarnings("unused")
  public CertificateCredentialValue() {
    super();
  }

  public CertificateCredentialValue(
    final String ca,
    final String certificate,
    final String privateKey,
    final String caName) {
    this(ca, certificate, privateKey, caName, false);
  }

  public CertificateCredentialValue(
    final String ca,
    final String certificate,
    final String privateKey,
    final String caName,
    final boolean transitional) {
    super();
    this.ca = ca;
    this.certificate = certificate;
    this.privateKey = privateKey;
    this.transitional = transitional;
    setCaName(caName);
  }

  public String getCa() {
    return ca;
  }

  public void setCa(final String ca) {
    this.ca = ca;
  }

  public String getCertificate() {
    return certificate;
  }

  public String getPrivateKey() {
    return privateKey;
  }

  public String getCaName() {
    return caName;
  }

  public void setCaName(final String caName) {
    this.caName = StringUtils.prependIfMissing(caName, "/");
  }

  public boolean isTransitional() {
    return transitional;
  }

  public void setTransitional(final boolean transitional) {
    this.transitional = transitional;
  }

  public Instant getExpiryDate() {
    return new CertificateReader(certificate).getNotAfter();
  }
}
