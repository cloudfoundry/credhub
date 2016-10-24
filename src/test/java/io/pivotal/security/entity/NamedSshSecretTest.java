package io.pivotal.security.entity;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.fake.FakeEncryptionService;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.EncryptionService;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test", "FakeEncryptionService"})
public class NamedSshSecretTest {
  @Autowired
  SecretRepository repository;

  @Autowired
  EncryptionService encryptionService;

  private NamedSshSecret subject;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      subject = new NamedSshSecret("Foo");
      ((FakeEncryptionService) encryptionService).resetEncryptionCount();
    });

    it("sets a public key", () -> {
      subject
          .setPublicKey("my-public-key");
      repository.saveAndFlush(subject);
      NamedSshSecret result = (NamedSshSecret) repository.findOne(subject.getId());
      assertThat(result.getPublicKey(), equalTo("my-public-key"));
    });

    it("sets an encrypted private key", () -> {
      subject
          .setPrivateKey("some-private-value");
      repository.saveAndFlush(subject);

      NamedSshSecret result = (NamedSshSecret) repository.findOne(subject.getId());

      assertThat(result.getPrivateKey(), equalTo("some-private-value"));
    });

    it("updates the private key value with the same name when overwritten", () -> {
      subject.setPrivateKey("first");
      repository.saveAndFlush(subject);

      subject.setPrivateKey("second");
      repository.saveAndFlush(subject);

      NamedSshSecret result = (NamedSshSecret) repository.findOne(subject.getId());
      assertThat(result.getPrivateKey(), equalTo("second"));
    });

    describe("getKeyLength", () -> {
      it("should return the length of the public key (when no comment)", () -> {
        // generate with ./build/credhub n -t ssh -n foo -k 4096
        String publicKeyOfLength4096 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC5aExadHpLn57Ms7bDkcjq/Zc8QGH1geBvx52SZCl7r+No5LaTQ8dYNlhYx60Edw3JbB/46dwPq/YkYjJSHzMpP3vizyoqGi2MZBgx98t3CrgwGH0SZEa4lPnivhedyxnWNbnoQbQW4Hq+9sp3WVOnsJBBCV6mG+guEonJnXEhSkl9Xey459787zs1yfSvXoE8pIZBQhFU10iz0sYcmpV3NuE2A5kepkCzeWzS0kUnkLeN+CD7KeYSf8zZ6HfAnEcnOrOzbFJ9r9fMe2SrVxRj0sqGyAOTGxw3+FRqWEyhQHWQDu0t+DxGkKlDlHIYlmna1KMqFT256QCqVsjQoTgnBvIj8cbO/EfojcLyRpDG2NM1Y5ogefK+MdTzwGPlgkMMgBWumyKnRHhsNRCRCKdByUvUB9CFoosiiMC5JYdf7qD2usazRj9/fOQ3qZ+0lAAEBj8+52cvb38xXXR9bGItm7Bh+JGexotRpmitZbiV7arHYckI2r4kkoxsCzCSDoUPF/qWS2p65ic6s0LJKGOpEFS0rBgX5rcn+3b7PFsVflhBTaENCnxF0sCaNaD1w0BwNf5WNK/I0I+h7E15wYXI8ywJLsHuzcOVTcm7ab5pvX/E4RX0HsRTLzu6nAZWVGmwrYf7iRA5UzdnAaajXSlxtk4kNtActSCtmMc+EHkLkQ==";

        subject.setPublicKey(publicKeyOfLength4096);

        assertThat(subject.getKeyLength(), equalTo(4096));
      });

      it("should still return the length when there is a comment", () -> {
        // generate with ./build/credhub n -t ssh -n foo -k 4096
        String publicKeyOfLength4096 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC5aExadHpLn57Ms7bDkcjq/Zc8QGH1geBvx52SZCl7r+No5LaTQ8dYNlhYx60Edw3JbB/46dwPq/YkYjJSHzMpP3vizyoqGi2MZBgx98t3CrgwGH0SZEa4lPnivhedyxnWNbnoQbQW4Hq+9sp3WVOnsJBBCV6mG+guEonJnXEhSkl9Xey459787zs1yfSvXoE8pIZBQhFU10iz0sYcmpV3NuE2A5kepkCzeWzS0kUnkLeN+CD7KeYSf8zZ6HfAnEcnOrOzbFJ9r9fMe2SrVxRj0sqGyAOTGxw3+FRqWEyhQHWQDu0t+DxGkKlDlHIYlmna1KMqFT256QCqVsjQoTgnBvIj8cbO/EfojcLyRpDG2NM1Y5ogefK+MdTzwGPlgkMMgBWumyKnRHhsNRCRCKdByUvUB9CFoosiiMC5JYdf7qD2usazRj9/fOQ3qZ+0lAAEBj8+52cvb38xXXR9bGItm7Bh+JGexotRpmitZbiV7arHYckI2r4kkoxsCzCSDoUPF/qWS2p65ic6s0LJKGOpEFS0rBgX5rcn+3b7PFsVflhBTaENCnxF0sCaNaD1w0BwNf5WNK/I0I+h7E15wYXI8ywJLsHuzcOVTcm7ab5pvX/E4RX0HsRTLzu6nAZWVGmwrYf7iRA5UzdnAaajXSlxtk4kNtActSCtmMc+EHkLkQ== dan@foo";

        subject.setPublicKey(publicKeyOfLength4096);

        assertThat(subject.getKeyLength(), equalTo(4096));
      });
    });

    describe("getComment", () -> {
      it("should return a comment when there is one", () -> {
        // generate with ./build/credhub n -t ssh -n foo -k 4096
        String publicKeyWithComment = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC5aExadHpLn57Ms7bDkcjq/Zc8QGH1geBvx52SZCl7r+No5LaTQ8dYNlhYx60Edw3JbB/46dwPq/YkYjJSHzMpP3vizyoqGi2MZBgx98t3CrgwGH0SZEa4lPnivhedyxnWNbnoQbQW4Hq+9sp3WVOnsJBBCV6mG+guEonJnXEhSkl9Xey459787zs1yfSvXoE8pIZBQhFU10iz0sYcmpV3NuE2A5kepkCzeWzS0kUnkLeN+CD7KeYSf8zZ6HfAnEcnOrOzbFJ9r9fMe2SrVxRj0sqGyAOTGxw3+FRqWEyhQHWQDu0t+DxGkKlDlHIYlmna1KMqFT256QCqVsjQoTgnBvIj8cbO/EfojcLyRpDG2NM1Y5ogefK+MdTzwGPlgkMMgBWumyKnRHhsNRCRCKdByUvUB9CFoosiiMC5JYdf7qD2usazRj9/fOQ3qZ+0lAAEBj8+52cvb38xXXR9bGItm7Bh+JGexotRpmitZbiV7arHYckI2r4kkoxsCzCSDoUPF/qWS2p65ic6s0LJKGOpEFS0rBgX5rcn+3b7PFsVflhBTaENCnxF0sCaNaD1w0BwNf5WNK/I0I+h7E15wYXI8ywJLsHuzcOVTcm7ab5pvX/E4RX0HsRTLzu6nAZWVGmwrYf7iRA5UzdnAaajXSlxtk4kNtActSCtmMc+EHkLkQ== dan@foo";

        subject.setPublicKey(publicKeyWithComment);

        assertThat(subject.getComment(), equalTo("dan@foo"));
      });

      it("should return a empty string when there is none", () -> {
        // generate with ./build/credhub n -t ssh -n foo -k 4096
        String publicKeyWithComment = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC5aExadHpLn57Ms7bDkcjq/Zc8QGH1geBvx52SZCl7r+No5LaTQ8dYNlhYx60Edw3JbB/46dwPq/YkYjJSHzMpP3vizyoqGi2MZBgx98t3CrgwGH0SZEa4lPnivhedyxnWNbnoQbQW4Hq+9sp3WVOnsJBBCV6mG+guEonJnXEhSkl9Xey459787zs1yfSvXoE8pIZBQhFU10iz0sYcmpV3NuE2A5kepkCzeWzS0kUnkLeN+CD7KeYSf8zZ6HfAnEcnOrOzbFJ9r9fMe2SrVxRj0sqGyAOTGxw3+FRqWEyhQHWQDu0t+DxGkKlDlHIYlmna1KMqFT256QCqVsjQoTgnBvIj8cbO/EfojcLyRpDG2NM1Y5ogefK+MdTzwGPlgkMMgBWumyKnRHhsNRCRCKdByUvUB9CFoosiiMC5JYdf7qD2usazRj9/fOQ3qZ+0lAAEBj8+52cvb38xXXR9bGItm7Bh+JGexotRpmitZbiV7arHYckI2r4kkoxsCzCSDoUPF/qWS2p65ic6s0LJKGOpEFS0rBgX5rcn+3b7PFsVflhBTaENCnxF0sCaNaD1w0BwNf5WNK/I0I+h7E15wYXI8ywJLsHuzcOVTcm7ab5pvX/E4RX0HsRTLzu6nAZWVGmwrYf7iRA5UzdnAaajXSlxtk4kNtActSCtmMc+EHkLkQ==";

        subject.setPublicKey(publicKeyWithComment);

        assertThat(subject.getComment(), equalTo(""));
      });

      it("should return all parts of a comment with spaces in it", () -> {
        String publicKeyWithComment = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC5aExadHpLn57Ms7bDkcjq/Zc8QGH1geBvx52SZCl7r+No5LaTQ8dYNlhYx60Edw3JbB/46dwPq/YkYjJSHzMpP3vizyoqGi2MZBgx98t3CrgwGH0SZEa4lPnivhedyxnWNbnoQbQW4Hq+9sp3WVOnsJBBCV6mG+guEonJnXEhSkl9Xey459787zs1yfSvXoE8pIZBQhFU10iz0sYcmpV3NuE2A5kepkCzeWzS0kUnkLeN+CD7KeYSf8zZ6HfAnEcnOrOzbFJ9r9fMe2SrVxRj0sqGyAOTGxw3+FRqWEyhQHWQDu0t+DxGkKlDlHIYlmna1KMqFT256QCqVsjQoTgnBvIj8cbO/EfojcLyRpDG2NM1Y5ogefK+MdTzwGPlgkMMgBWumyKnRHhsNRCRCKdByUvUB9CFoosiiMC5JYdf7qD2usazRj9/fOQ3qZ+0lAAEBj8+52cvb38xXXR9bGItm7Bh+JGexotRpmitZbiV7arHYckI2r4kkoxsCzCSDoUPF/qWS2p65ic6s0LJKGOpEFS0rBgX5rcn+3b7PFsVflhBTaENCnxF0sCaNaD1w0BwNf5WNK/I0I+h7E15wYXI8ywJLsHuzcOVTcm7ab5pvX/E4RX0HsRTLzu6nAZWVGmwrYf7iRA5UzdnAaajXSlxtk4kNtActSCtmMc+EHkLkQ== comment with spaces";

        subject.setPublicKey(publicKeyWithComment);

        assertThat(subject.getComment(), equalTo("comment with spaces"));
      });
    });
  }
}
