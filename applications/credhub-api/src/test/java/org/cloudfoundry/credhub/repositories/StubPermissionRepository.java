package org.cloudfoundry.credhub.repositories;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.data.PermissionData;

@SuppressFBWarnings(
  value = "NP_NONNULL_RETURN_VIOLATION",
  justification = "We don't need most of these methods to actually return anything."
)
public class StubPermissionRepository implements PermissionRepository {

  private PermissionData return_findByPathAndAnchor;

  public void setReturn_findByPathAndAnchor(final PermissionData permissionData) {
    this.return_findByPathAndAnchor = permissionData;
  }

  @Override
  public PermissionData findByPathAndActor(final String path, final String actor) {
    return return_findByPathAndAnchor;
  }

  @Override
  public List<PermissionData> findAllByPath(final String path) {
    return null;
  }

  @Override
  public List<PermissionData> findAllByActor(final String actor) {
    return null;
  }

  @Override
  public PermissionData findByUuid(final UUID uuid) {
    return null;
  }

  @Override
  public List<PermissionData> findByPathsAndActor(final List<String> paths, final String actor) {
    return null;
  }

  @Override
  public List<String> findAllPathsForActorWithReadPermission(final String actor) {
    return null;
  }

  @Override
  public long deleteByPathAndActor(final String path, final String actor) {
    return 0;
  }

  @Override
  public List<PermissionData> findAll() {
    return null;
  }

  @Override
  public List<PermissionData> findAll(final Sort sort) {
    return null;
  }

  @Override
  public Page<PermissionData> findAll(final Pageable pageable) {
    return null;
  }

  @Override
  public List<PermissionData> findAllById(final Iterable<UUID> uuids) {
    return null;
  }

  @Override
  public long count() {
    return 0;
  }

  @Override
  public void deleteById(final UUID uuid) {

  }

  @Override
  public void delete(final PermissionData entity) {

  }

  @Override
  public void deleteAll(final Iterable<? extends PermissionData> entities) {

  }

  @Override
  public void deleteAll() {

  }

  @Override
  public <S extends PermissionData> S save(final S entity) {
    return null;
  }

  @Override
  public <S extends PermissionData> List<S> saveAll(final Iterable<S> entities) {
    return null;
  }

  @Override
  public Optional<PermissionData> findById(final UUID uuid) {
    return Optional.empty();
  }

  @Override
  public boolean existsById(final UUID uuid) {
    return false;
  }

  @Override
  public void flush() {

  }

  @Override
  public <S extends PermissionData> S saveAndFlush(final S entity) {
    return null;
  }

  @Override
  public void deleteInBatch(final Iterable<PermissionData> entities) {

  }

  @Override
  public void deleteAllInBatch() {

  }

  @Override
  public PermissionData getOne(final UUID uuid) {
    return null;
  }

  @Override
  public <S extends PermissionData> Optional<S> findOne(final Example<S> example) {
    return Optional.empty();
  }

  @Override
  public <S extends PermissionData> List<S> findAll(final Example<S> example) {
    return null;
  }

  @Override
  public <S extends PermissionData> List<S> findAll(final Example<S> example, final Sort sort) {
    return null;
  }

  @Override
  public <S extends PermissionData> Page<S> findAll(final Example<S> example, final Pageable pageable) {
    return null;
  }

  @Override
  public <S extends PermissionData> long count(final Example<S> example) {
    return 0;
  }

  @Override
  public <S extends PermissionData> boolean exists(final Example<S> example) {
    return false;
  }
}
