package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.DatabindContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.jsontype.TypeIdResolver;
import io.pivotal.security.entity.CertificateCredentialData;
import io.pivotal.security.entity.JsonCredentialData;
import io.pivotal.security.entity.PasswordCredentialData;
import io.pivotal.security.entity.RsaCredentialData;
import io.pivotal.security.entity.SshCredentialData;
import io.pivotal.security.entity.UserCredentialData;
import io.pivotal.security.entity.ValueCredentialData;

import java.io.IOException;

public class SetRequestTypeIdResolver implements TypeIdResolver {
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
    Class<?> subType;
    id = id.toLowerCase();

    switch (id) {
      case CertificateCredentialData.CREDENTIAL_TYPE:
        subType = CertificateSetRequest.class;
        break;
      case ValueCredentialData.CREDENTIAL_TYPE:
        subType = ValueSetRequest.class;
        break;
      case JsonCredentialData.CREDENTIAL_TYPE:
        subType = JsonSetRequest.class;
        break;
      case PasswordCredentialData.CREDENTIAL_TYPE:
        subType = PasswordSetRequest.class;
        break;
      case RsaCredentialData.CREDENTIAL_TYPE:
        subType = RsaSetRequest.class;
        break;
      case SshCredentialData.CREDENTIAL_TYPE:
        subType = SshSetRequest.class;
        break;
      case UserCredentialData.CREDENTIAL_TYPE:
        subType = UserSetRequest.class;
        break;
      default:
        String message = String.format("Could not resolve type id '%s' into a subtype of %s", id, baseType);
        throw new InvalidTypeIdException(null, message, baseType, id);
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
