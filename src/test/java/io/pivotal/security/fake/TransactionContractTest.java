package io.pivotal.security.fake;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.entity.OperationAuditRecord;
import java.time.Instant;
import org.junit.runner.RunWith;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

@RunWith(Spectrum.class)
public class TransactionContractTest {

  FakeSecretRepository secretRepository;

  FakeOperationAuditRecordRepository auditRecordRepository;

  FakeTransactionManager transactionManager;

  TransactionStatus transaction;

  {
    beforeEach(() -> {
      transactionManager = new FakeTransactionManager();
      secretRepository = new FakeSecretRepository(transactionManager);
      auditRecordRepository = new FakeOperationAuditRecordRepository(transactionManager);
    });

    describe("a transaction", () -> {
      beforeEach(() -> {
        transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
      });

      itThrows("does not allow nesting", RuntimeException.class, () -> {
        transactionManager.getTransaction(new DefaultTransactionDefinition());
      });

      describe("audit repository in dangerous mode when saving", () -> {
        beforeEach(() -> {
          auditRecordRepository.failOnSave();
        });

        itThrows("save audit record", RuntimeException.class, () -> {
          auditRecordRepository.save(new OperationAuditRecord());
        });

        it("has an open transaction", () -> {
          assertThat(transactionManager.hasOpenTransaction(), is(true));
        });
      });

      describe("transaction manager in dangerous mode when commiting", () -> {
        beforeEach(() -> {
          transactionManager.failOnCommit();
        });

        itThrows("save audit record", RuntimeException.class, () -> {
          transactionManager.commit(transaction);
        });
      });

      describe("when data has been written", () -> {
        beforeEach(() -> {
          NamedValueSecretData entity = new NamedValueSecretData("test");
          entity.setEncryptedValue("value".getBytes());
          secretRepository.save(entity);
          NamedValueSecretData namedValueSecret = new NamedValueSecretData("otherTest");
          namedValueSecret.setEncryptedValue("otherValue".getBytes());
          secretRepository.save(namedValueSecret);

          final OperationAuditRecord auditRecord = new OperationAuditRecord("", Instant.now(),
              null, "operation", null, null,
              null, 0L, 0L, null, null,
              null, null, 0, null, null,
              null, null, null, true);
          auditRecordRepository.save(auditRecord);
        });

        describe("after a commit", () -> {
          beforeEach(() -> {
            transactionManager.commit(transaction);
          });

          it("is visible", () -> {
            assertThat(secretRepository.count(), equalTo(2L));
            assertThat(auditRecordRepository.count(), equalTo(1L));
            assertThat(auditRecordRepository.findAll().get(0).getOperation(), equalTo("operation"));
          });

          itThrows("can't be rolled back", RuntimeException.class, () -> {
            transactionManager.rollback(transaction);
          });
        });

        describe("after a rollback", () -> {
          beforeEach(() -> {
            transactionManager.rollback(transaction);
          });

          it("revokes the data", () -> {
            assertThat(secretRepository.count(), equalTo(0L));
            assertThat(auditRecordRepository.count(), equalTo(0L));
          });

          describe("when another transaction is opened", () -> {
            beforeEach(() -> {
              transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
              NamedValueSecretData entity = new NamedValueSecretData("test3");
              entity.setEncryptedValue("value3".getBytes());
              secretRepository.save(entity);
              transactionManager.commit(transaction);
            });

            it("it works as usual", () -> {
              assertThat(secretRepository.count(), equalTo(1L));
            });
          });
        });
      });
    });
  }
}
