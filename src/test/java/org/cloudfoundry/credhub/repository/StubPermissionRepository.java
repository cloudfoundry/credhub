package org.cloudfoundry.credhub.repository;

import org.cloudfoundry.credhub.entity.PermissionData;
import org.cloudfoundry.credhub.repository.PermissionRepository;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Repository;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static java.util.Collections.emptyList;

public class StubPermissionRepository implements PermissionRepository {

  private PermissionData return_findByPathAndAnchor;

  public void setReturn_findByPathAndAnchor(PermissionData permissionData) {
    this.return_findByPathAndAnchor = permissionData;
  }

  @Override
  public PermissionData findByPathAndActor(String path, String actor) {
    return return_findByPathAndAnchor;
  }

  @Override
  public List<PermissionData> findAllByPath(String path) {
    return null;
  }

  @Override
  public List<PermissionData> findAllByActor(String actor) {
    return null;
  }

  @Override
  public PermissionData findByUuid(UUID uuid) {
    return null;
  }

  @Override
  public List<PermissionData> findByPathsAndActor(List<String> paths, String actor) {
    return null;
  }

  @Override
  public List<String> findAllPathsForActorWithReadPermission(String actor) {
    return null;
  }

  @Override
  public long deleteByPathAndActor(String path, String actor) {
    return 0;
  }

  @Override
  public List<PermissionData> findAll() {
    return null;
  }

  @Override
  public List<PermissionData> findAll(Sort sort) {
    return null;
  }

  @Override
  public Page<PermissionData> findAll(Pageable pageable) {
    return null;
  }

  @Override
  public List<PermissionData> findAllById(Iterable<UUID> uuids) {
    return null;
  }

  @Override
  public long count() {
    return 0;
  }

  @Override
  public void deleteById(UUID uuid) {

  }

  @Override
  public void delete(PermissionData entity) {

  }

  @Override
  public void deleteAll(Iterable<? extends PermissionData> entities) {

  }

  @Override
  public void deleteAll() {

  }

  @Override
  public <S extends PermissionData> S save(S entity) {
    return null;
  }

  @Override
  public <S extends PermissionData> List<S> saveAll(Iterable<S> entities) {
    return null;
  }

  @Override
  public Optional<PermissionData> findById(UUID uuid) {
    return Optional.empty();
  }

  @Override
  public boolean existsById(UUID uuid) {
    return false;
  }

  @Override
  public void flush() {

  }

  @Override
  public <S extends PermissionData> S saveAndFlush(S entity) {
    return null;
  }

  @Override
  public void deleteInBatch(Iterable<PermissionData> entities) {

  }

  @Override
  public void deleteAllInBatch() {

  }

  @Override
  public PermissionData getOne(UUID uuid) {
    return null;
  }

  @Override
  public <S extends PermissionData> Optional<S> findOne(Example<S> example) {
    return Optional.empty();
  }

  @Override
  public <S extends PermissionData> List<S> findAll(Example<S> example) {
    return null;
  }

  @Override
  public <S extends PermissionData> List<S> findAll(Example<S> example, Sort sort) {
    return null;
  }

  @Override
  public <S extends PermissionData> Page<S> findAll(Example<S> example, Pageable pageable) {
    return null;
  }

  @Override
  public <S extends PermissionData> long count(Example<S> example) {
    return 0;
  }

  @Override
  public <S extends PermissionData> boolean exists(Example<S> example) {
    return false;
  }
}
