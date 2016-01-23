/*
 * Copyright 2014 Red Hat, Inc.
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

package io.vertx.ext.auth.jdbc.impl;

import java.util.Optional;
import java.util.function.Consumer;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jdbc.JDBCAuth;
import io.vertx.ext.auth.jdbc.JDBCAuthOptions;
import io.vertx.ext.auth.jdbc.PasswordStrategy;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.sql.ResultSet;
import io.vertx.ext.sql.SQLConnection;

/**
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class JDBCAuthImpl implements AuthProvider, JDBCAuth {

  private JDBCClient client;
  private String authenticateQuery = JDBCAuthOptions.DEFAULT_AUTHENTICATE_QUERY;
  private String rolesQuery = JDBCAuthOptions.DEFAULT_ROLES_QUERY;
  private String permissionsQuery = JDBCAuthOptions.DEFAULT_PERMISSIONS_QUERY;
  private String rolePrefix = JDBCAuthOptions.DEFAULT_ROLE_PREFIX;
  private PasswordStrategy strategy = new SaltedHashPasswordStrategy("SHA-512");

  public JDBCAuthImpl(JDBCClient client) {
    this.client = client;
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {

    String username = authInfo.getString("username");
    if (username == null) {
      resultHandler.handle(Future.failedFuture("authInfo must contain username in 'username' field"));
      return;
    }
    String password = authInfo.getString("password");
    if (password == null) {
      resultHandler.handle(Future.failedFuture("authInfo must contain password in 'password' field"));
      return;
    }
    executeQuery(authenticateQuery, new JsonArray().add(username), resultHandler, rs -> {

      switch (rs.getNumRows()) {
        case 1: {
          JsonArray row = rs.getResults().get(0);
          String hashedStoredPwd = strategy.getPasswordFromQueryResult(row);
          Optional<String> salt = strategy.getSaltFromQueryResult(row);
          String hashedPassword = strategy.compute(password, salt);
          if (hashedStoredPwd.equals(hashedPassword)) {
            resultHandler.handle(Future.succeededFuture(new JDBCUser(username, this, rolePrefix)));
            break;
          }
        }
        default: {
          // More than one row returned - keep the same error message to not leak any information
          resultHandler.handle(Future.failedFuture("Invalid username/password"));
          break;
        }
      }
    });
  }

  @Override
  public JDBCAuth setAuthenticationQuery(String authenticationQuery) {
    this.authenticateQuery = authenticationQuery;
    return this;
  }

  @Override
  public JDBCAuth setRolesQuery(String rolesQuery) {
    this.rolesQuery = rolesQuery;
    return this;
  }

  @Override
  public JDBCAuth setPermissionsQuery(String permissionsQuery) {
    this.permissionsQuery = permissionsQuery;
    return this;
  }

  @Override
  public JDBCAuth setRolePrefix(String rolePrefix) {
    this.rolePrefix = rolePrefix;
    return this;
  }

  @Override
  public JDBCAuth setPasswordStrategy(PasswordStrategy strategy) {
    this.strategy = strategy;
    return this;
  }

  protected <T> void executeQuery(String query, JsonArray params,
      Handler<AsyncResult<T>> resultHandler, Consumer<ResultSet> resultSetConsumer) {
    client.getConnection(res -> {
      if (res.succeeded()) {
        SQLConnection conn = res.result();
        conn.queryWithParams(query, params, queryRes -> {
          if (queryRes.succeeded()) {
            ResultSet rs = queryRes.result();
            resultSetConsumer.accept(rs);
          } else {
            resultHandler.handle(Future.failedFuture(queryRes.cause()));
          }
          conn.close(closeRes -> {});
        });
      } else {
        resultHandler.handle(Future.failedFuture(res.cause()));
      }
    });
  }

  String getRolesQuery() {
    return rolesQuery;
  }

  String getPermissionsQuery() {
    return permissionsQuery;
  }

}
