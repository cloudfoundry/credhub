package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.DatabindContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.jsontype.TypeIdResolver;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.JsonCredentialVersionData;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.entity.RsaCredentialVersionData;
import org.cloudfoundry.credhub.entity.SshCredentialVersionData;
import org.cloudfoundry.credhub.entity.UserCredentialVersionData;
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData;

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
      case CertificateCredentialVersionData.CREDENTIAL_TYPE:
        subType = CertificateSetRequest.class;
        break;
      case ValueCredentialVersionData.CREDENTIAL_TYPE:
        subType = ValueSetRequest.class;
        break;
      case JsonCredentialVersionData.CREDENTIAL_TYPE:
        subType = JsonSetRequest.class;
        break;
      case PasswordCredentialVersionData.CREDENTIAL_TYPE:
        subType = PasswordSetRequest.class;
        break;
      case RsaCredentialVersionData.CREDENTIAL_TYPE:
        subType = RsaSetRequest.class;
        break;
      case SshCredentialVersionData.CREDENTIAL_TYPE:
        subType = SshSetRequest.class;
        break;
      case UserCredentialVersionData.CREDENTIAL_TYPE:
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
