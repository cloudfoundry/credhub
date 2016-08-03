package io.pivotal.security.fake;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.entity.OperationAuditRecord;
import org.junit.runner.RunWith;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(Spectrum.class)
public class TransactionContractTest {

  FakeSecretRepository secretRepository;

  FakeAuditRecordRepository auditRecordRepository;

  FakeTransactionManager transactionManager;

  TransactionStatus transaction;

  {
    beforeEach(() -> {
      transactionManager = new FakeTransactionManager();
      secretRepository = new FakeSecretRepository(transactionManager);
      auditRecordRepository = new FakeAuditRecordRepository(transactionManager);
    });

    describe("a transaction", () -> {
      beforeEach(() -> {
        transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
      });

      itThrows("does not allow nesting", RuntimeException.class, () -> {
        transactionManager.getTransaction(new DefaultTransactionDefinition());
      });

      describe("audit repository in dangerous mode", () -> {
        beforeEach(() -> {
          auditRecordRepository.makeDangerous();
        });

        itThrows("save audit record", RuntimeException.class, () -> {
          auditRecordRepository.save(new OperationAuditRecord());
        });
      });

      describe("when data has been written", () -> {
        beforeEach(() -> {
          secretRepository.save(new NamedStringSecret("test").setValue("value"));
          secretRepository.save(new NamedStringSecret("otherTest").setValue("otherValue"));

          final OperationAuditRecord auditRecord = new OperationAuditRecord();
          auditRecord.setOperation("operation");
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
              secretRepository.save(new NamedStringSecret("test3").setValue("value3"));
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
