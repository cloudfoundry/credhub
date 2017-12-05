package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.DatabindContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.jsontype.TypeIdResolver;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.entity.RsaCredentialVersionData;
import org.cloudfoundry.credhub.entity.SshCredentialVersionData;
import org.cloudfoundry.credhub.entity.UserCredentialVersionData;

import java.io.IOException;

public class GenerateRequestTypeIdResolver implements TypeIdResolver {
  private JavaType baseType;

  @Override
  public void init(JavaType baseType) {
    this.baseType = baseType;
  }

  @Override
  public String idFromValue(Object value) {
    return null;
  }

  @Override
  public String idFromValueAndType(Object value, Class<?> suggestedType) {
    return null;
  }

  @Override
  public String idFromBaseType() {
    return null;
  }

  @Override
  public JavaType typeFromId(DatabindContext context, String id) throws IOException {
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
