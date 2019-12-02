package org.cloudfoundry.credhub.views;

import java.time.Instant;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;

@SuppressWarnings("unused")
public class CertificateView extends CredentialView {
    @JsonIgnore
    private boolean concatenateCas;
    private CertificateCredentialVersion version;

    private Instant expiryDate;
    private boolean certificateAuthority;
    private boolean selfSigned;
    @JsonInclude(Include.NON_NULL)
    private Boolean generated;

    CertificateView() {
        super(); /* Jackson */
    }

    public CertificateView(final CertificateCredentialVersion version) {
        super(
            version.getVersionCreatedAt(),
            version.getUuid(),
            version.getName(),
            version.getCredentialType(),
            null
        );
        this.version = version;
        this.expiryDate = version.getExpiryDate();
        this.certificateAuthority = version.isCertificateAuthority();
        this.selfSigned = version.isSelfSigned();
        this.generated = version.getGenerated();
        this.concatenateCas = false;
    }

    public CertificateView(final CertificateCredentialVersion version, final boolean concatenateCas) {
        super(
          version.getVersionCreatedAt(),
          version.getUuid(),
          version.getName(),
          version.getCredentialType(),
          null
        );
        this.version = version;
        this.expiryDate = version.getExpiryDate();
        this.certificateAuthority = version.isCertificateAuthority();
        this.selfSigned = version.isSelfSigned();
        this.generated = version.getGenerated();
        this.concatenateCas = concatenateCas;
    }

    @Override
    public CredentialValue getValue() {
        return new CertificateValueView(version, concatenateCas);
    }

    public boolean isTransitional() {
        return version.isVersionTransitional();
    }

    public Instant getExpiryDate() {
        return expiryDate;
    }

    public boolean isCertificateAuthority() {
        return certificateAuthority;
    }

    public boolean isSelfSigned() {
        return selfSigned;
    }

    public Boolean getGenerated() {
        return generated;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        final CertificateView that = (CertificateView) o;
        return certificateAuthority == that.certificateAuthority &&
                selfSigned == that.selfSigned &&
                Objects.equals(generated, that.generated) &&
                Objects.equals(version, that.version) &&
                Objects.equals(expiryDate, that.expiryDate);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), version, expiryDate, certificateAuthority, selfSigned, generated);
    }
}
