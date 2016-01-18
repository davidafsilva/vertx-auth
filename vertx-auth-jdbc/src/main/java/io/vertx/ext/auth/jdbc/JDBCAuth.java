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

package io.vertx.ext.auth.jdbc;

import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.jdbc.impl.JDBCAuthImpl;
import io.vertx.ext.jdbc.JDBCClient;

/**
 * Factory interface for creating {@link io.vertx.ext.auth.AuthProvider} instances that use the Vert.x JDBC client
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@VertxGen
public interface JDBCAuth extends AuthProvider {

  /**
   * Create a JDBC auth provider implementation
   *
   * @param client  the JDBC client instance
   * @return  the auth provider
   */
  static JDBCAuth create(JDBCClient client) {
    return new JDBCAuthImpl(client);
  }

  /**
   * Set the authentication query to use. Use this if you want to override the default authentication query.
   * @param authenticationQuery  the authentication query
   * @return  a reference to this for fluency
   */
  JDBCAuth setAuthenticationQuery(String authenticationQuery);

  /**
   * Set the roles query to use. Use this if you want to override the default roles query.
   * @param rolesQuery  the roles query
   * @return  a reference to this for fluency
   */
  JDBCAuth setRolesQuery(String rolesQuery);

  /**
   * Set the permissions query to use. Use this if you want to override the default permissions query.
   * @param permissionsQuery  the permissions query
   * @return  a reference to this for fluency
   */
  JDBCAuth setPermissionsQuery(String permissionsQuery);

  /**
   * Set the role prefix to distinguish from permissions when checking for isPermitted requests.
   * @param rolePrefix a Prefix e.g.: "role:"
   * @return a reference to this for fluency
   */
  JDBCAuth setRolePrefix(String rolePrefix);

  /**
   * Set the hash strategy to use. Use this if you want override the default hash strategy
   * @param strategy  the strategy
   * @return a reference to this for fluency
   */
  @GenIgnore
  JDBCAuth setHashStrategy(PasswordStrategy strategy);

}
