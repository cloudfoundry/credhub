package org.cloudfoundry.credhub.entities;

import org.hibernate.HibernateException;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.id.UUIDGenerator;

@SuppressWarnings("unused")
public class UuidGenerator extends UUIDGenerator {
  @Override
  public boolean allowAssignedIdentifiers() {
    return true;
  }

  @Override
  public Object generate(final SharedSessionContractImplementor session, final Object object) throws HibernateException {
    final Object uuid = session.getEntityPersister(null, object)
      .getClassMetadata().getIdentifier(object, session);

    return uuid != null ? uuid : super.generate(session, object);
  }
}
