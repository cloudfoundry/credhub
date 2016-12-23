package io.pivotal.security.entity;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.fake.FakeEncryptionService;
import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertNotNull;

import java.time.Instant;
import java.util.UUID;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test", "FakeEncryptionService"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class NamedSshSecretTest {
  @Autowired
  EncryptionService encryptionService;

  @Autowired
  SecretEncryptionHelper secretEncryptionHelper;

  private NamedSshSecret subject;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      subject = new NamedSshSecret("Foo");
      ((FakeEncryptionService) encryptionService).resetEncryptionCount();
    });

    it("returns type ssh", () -> {
      assertThat(subject.getSecretType(), equalTo("ssh"));
    });

    it("sets an encrypted private key", () -> {
      subject.setPrivateKey("some-private-value");

      assertNotNull(subject.getEncryptedValue());
      assertNotNull(subject.getNonce());

      assertThat(secretEncryptionHelper.retrieveClearTextValue(subject), equalTo("some-private-value"));
    });

    describe("#getKeyLength", () -> {
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

    describe("#getComment", () -> {
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

    describe("#copyInto", () -> {
      it("should copy the correct properties into the other object", () -> {
        Instant frozenTime = Instant.ofEpochSecond(1400000000L);
        UUID uuid = UUID.randomUUID();

        subject = new NamedSshSecret("foo");
        subject.setPublicKey("fake-public-key");
        subject.setPrivateKey("fake-private-key");
        subject.setUuid(uuid);
        subject.setUpdatedAt(frozenTime);

        NamedSshSecret copy = new NamedSshSecret();
        subject.copyInto(copy);

        assertThat(copy.getName(), equalTo("foo"));
        assertThat(copy.getPublicKey(), equalTo("fake-public-key"));
        assertThat(copy.getPrivateKey(), equalTo("fake-private-key"));

        assertThat(copy.getUuid(), not(equalTo(uuid)));
        assertThat(copy.getUpdatedAt(), not(equalTo(frozenTime)));
      });
    });
  }
}
