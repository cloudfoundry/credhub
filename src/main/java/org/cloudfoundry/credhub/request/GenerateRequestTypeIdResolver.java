package org.cloudfoundry.credhub.request;

import java.io.IOException;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.DatabindContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.jsontype.TypeIdResolver;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.entity.RsaCredentialVersionData;
import org.cloudfoundry.credhub.entity.SshCredentialVersionData;
import org.cloudfoundry.credhub.entity.UserCredentialVersionData;

public class GenerateRequestTypeIdResolver implements TypeIdResolver {
  private JavaType baseType;

  @Override
  public void init(final JavaType baseType) {
    this.baseType = baseType;
  }

  @Override
  public String idFromValue(final Object value) {
    return null;
  }

  @Override
  public String idFromValueAndType(final Object value, final Class<?> suggestedType) {
    return null;
  }

  @Override
  public String idFromBaseType() {
    return null;
  }

  @Override
  public JavaType typeFromId(final DatabindContext context, final String id) throws IOException {
    Class<?> subType = DefaultCredentialGenerateRequest.class;

    switch (id.toLowerCase()) {
      case CertificateCredentialVersionData.CREDENTIAL_TYPE:
        subType = CertificateGenerateRequest.class;
        break;
      case PasswordCredentialVersionData.CREDENTIAL_TYPE:
        subType = PasswordGenerateRequest.class;
        break;
      case RsaCredentialVersionData.CREDENTIAL_TYPE:
        subType = RsaGenerateRequest.class;
        break;
      case SshCredentialVersionData.CREDENTIAL_TYPE:
        subType = SshGenerateRequest.class;
        break;
      case UserCredentialVersionData.CREDENTIAL_TYPE:
        subType = UserGenerateRequest.class;
        break;
      default:
        break;
    }

    return context.constructSpecializedType(baseType, subType);
  }

  @Override
  public String getDescForKnownTypeIds() {
    return null;
  }

  @Override
  public JsonTypeInfo.Id getMechanism() {
    return JsonTypeInfo.Id.CUSTOM;
  }
}
