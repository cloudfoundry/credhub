package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.view.CertificateSecret;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.validation.ValidationException;

@Component
public class CertificateSetRequestTranslator implements SecretSetterRequestTranslator {

  @Override
  public CertificateSecret createSecretFromJson(DocumentContext parsed) throws ValidationException {
    String root = parsed.read("$.credential.root");
    String certificate = parsed.read("$.credential.certificate");
    String privateKey = parsed.read("$.credential.private");
    root = StringUtils.isEmpty(root) ? null : root;
    certificate = StringUtils.isEmpty(certificate) ? null : certificate;
    privateKey = StringUtils.isEmpty(privateKey) ? null : privateKey;
    if (root == null && certificate == null && privateKey == null) {
      throw new ValidationException("error.missing_certificate_credentials");
    }
    return new CertificateSecret(root, certificate, privateKey);
  }

  @Override
  public NamedSecret makeEntity(String name) {
    return new NamedCertificateSecret(name);
  }
}
