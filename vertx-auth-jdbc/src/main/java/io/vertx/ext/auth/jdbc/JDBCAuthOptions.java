/*
 * Copyright 2015 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */
package io.vertx.ext.auth.jdbc;

import java.util.Objects;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.jdbc.JDBCClient;

/**
 * Options configuring JDBC authentication.
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
@DataObject(generateConverter = true)
public class JDBCAuthOptions implements io.vertx.ext.auth.AuthOptions {

  /**
   * The default query to be used for authentication
   */
  public static final String DEFAULT_AUTHENTICATE_QUERY =
      "SELECT PASSWORD, PASSWORD_SALT FROM USER WHERE USERNAME = ?";

  /**
   * The default query to retrieve all roles for the user
   */
  public static final String DEFAULT_ROLES_QUERY =
      "SELECT ROLE FROM USER_ROLES WHERE USERNAME = ?";

  /**
   * The default query to retrieve all permissions for the role
   */
  public static final String DEFAULT_PERMISSIONS_QUERY =
      "SELECT PERM FROM ROLES_PERMS RP, USER_ROLES UR WHERE UR.USERNAME = ? AND UR.ROLE = RP.ROLE";

  /**
   * The default role prefix
   */
  public static final String DEFAULT_ROLE_PREFIX = "role:";

  private boolean shared = true;
  private String dataSourceName = JDBCClient.DEFAULT_DS_NAME;
  private String authenticationQuery = DEFAULT_AUTHENTICATE_QUERY;
  private String rolesQuery = DEFAULT_ROLES_QUERY;
  private String permissionsQuery = DEFAULT_PERMISSIONS_QUERY;
  private String rolesPrefix = DEFAULT_ROLE_PREFIX;
  private JsonObject config;

  public JDBCAuthOptions() {
  }

  public JDBCAuthOptions(JDBCAuthOptions that) {
    shared = that.shared;
    dataSourceName = that.dataSourceName;
    config = that.config != null ? that.config.copy() : null;
  }

  public JDBCAuthOptions(JsonObject json) {
    JDBCAuthOptionsConverter.fromJson(json, this);
  }

  @Override
  public JDBCAuthOptions clone() {
    return new JDBCAuthOptions(this);
  }

  @Override
  public JDBCAuth createProvider(Vertx vertx) {
    // create the JDBC client
    final JDBCClient client = shared ?
        JDBCClient.createShared(vertx, config, dataSourceName) :
        JDBCClient.createNonShared(vertx, config);
    // create the auth implementation
    return JDBCAuth.create(client)
        .setAuthenticationQuery(authenticationQuery)
        .setPermissionsQuery(permissionsQuery)
        .setRolesQuery(rolesQuery)
        .setRolePrefix(rolesPrefix);
  }

  public boolean isShared() {
    return shared;
  }

  /**
   * Set whether the JDBC client is shared or non shared.
   *
   * @param shared the sharing mode
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthOptions setShared(boolean shared) {
    this.shared = shared;
    return this;
  }

  public String getDataSourceName() {
    return dataSourceName;
  }

  /**
   * Set the data source name to use, only use in shared mode.
   *
   * @param dataSourceName the data source name
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthOptions setDataSourceName(String dataSourceName) {
    this.dataSourceName = Objects.requireNonNull(dataSourceName, "dataSourceName");
    return this;
  }

  public JsonObject getConfig() {
    return config;
  }

  /**
   * The configuration of the JDBC client: refer to the Vert.x JDBC Client configuration.
   *
   * @param config the JDBC client configuration
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthOptions setConfig(JsonObject config) {
    this.config = config;
    return this;
  }

  public String getAuthenticationQuery() {
    return authenticationQuery;
  }

  /**
   * Set the authentication query to use. Use this if you want to override the default
   * authentication query.
   *
   * @param authenticationQuery the authentication query
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthOptions setAuthenticationQuery(String authenticationQuery) {
    this.authenticationQuery = Objects.requireNonNull(authenticationQuery, "authenticationQuery");
    return this;
  }

  public String getRolesQuery() {
    return rolesQuery;
  }

  /**
   * Set the roles query to use. Use this if you want to override the default roles query.
   *
   * @param rolesQuery the roles query
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthOptions setRolesQuery(String rolesQuery) {
    this.rolesQuery = Objects.requireNonNull(rolesQuery, "rolesQuery");
    return this;
  }

  public String getPermissionsQuery() {
    return permissionsQuery;
  }

  /**
   * Set the permissions query to use. Use this if you want to override the default permissions
   * query.
   *
   * @param permissionsQuery the permissions query
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthOptions setPermissionsQuery(String permissionsQuery) {
    this.permissionsQuery = Objects.requireNonNull(permissionsQuery, "permissionsQuery");
    return this;
  }

  public String getRolesPrefix() {
    return rolesPrefix;
  }

  /**
   * Set the role prefix to distinguish from permissions when checking for isPermitted requests.
   *
   * @param rolesPrefix roles prefix
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthOptions setRolesPrefix(String rolesPrefix) {
    this.rolesPrefix = Objects.requireNonNull(rolesPrefix, "rolesPrefix");
    return this;
  }
}
