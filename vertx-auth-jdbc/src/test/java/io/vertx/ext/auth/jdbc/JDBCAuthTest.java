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

import org.junit.BeforeClass;
import org.junit.Test;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jdbc.impl.SaltedHashPasswordStrategy;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.test.core.VertxTestBase;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class JDBCAuthTest extends VertxTestBase {

  static final String HASH_ALGORITHM = "SHA-256";
  static final List<String> SQL = new ArrayList<>();

  static {
    SQL.add("drop table if exists user;");
    SQL.add("drop table if exists user_roles;");
    SQL.add("drop table if exists roles_perms;");
    SQL.add("create table user (username varchar(255), password varchar(255), password_salt varchar(255) );");
    SQL.add("create table user_roles (username varchar(255), role varchar(255));");
    SQL.add("create table roles_perms (role varchar(255), perm varchar(255));");

    SQL.add("insert into user values ('tim', 'IlyjozrPOpYmejRNoxijTbNn8NBBFNhKqJUsjY5CXzo=', 'R4direUPfPNIZoIiuaUI7+tcjqoZ9Fks8rrZc/0URvI=')");
    SQL.add("insert into user_roles values ('tim', 'dev');");
    SQL.add("insert into user_roles values ('tim', 'admin');");
    SQL.add("insert into roles_perms values ('dev', 'commit_code');");
    SQL.add("insert into roles_perms values ('dev', 'eat_pizza');");
    SQL.add("insert into roles_perms values ('admin', 'merge_pr');");

    // and a second set of tables with slight differences

    SQL.add("drop table if exists user2;");
    SQL.add("drop table if exists user_roles2;");
    SQL.add("drop table if exists roles_perms2;");
    SQL.add("create table user2 (user_name varchar(255), pwd varchar(255), pwd_salt varchar(255) );");
    SQL.add("create table user_roles2 (user_name varchar(255), role varchar(255));");
    SQL.add("create table roles_perms2 (role varchar(255), perm varchar(255));");

    SQL.add("insert into user2 values ('tim', 'IlyjozrPOpYmejRNoxijTbNn8NBBFNhKqJUsjY5CXzo=', 'R4direUPfPNIZoIiuaUI7+tcjqoZ9Fks8rrZc/0URvI=')");
    SQL.add("insert into user_roles2 values ('tim', 'dev');");
    SQL.add("insert into user_roles2 values ('tim', 'admin');");
    SQL.add("insert into roles_perms2 values ('dev', 'commit_code');");
    SQL.add("insert into roles_perms2 values ('dev', 'eat_pizza');");
    SQL.add("insert into roles_perms2 values ('admin', 'merge_pr');");

  }

  @BeforeClass
  public static void createDb() throws Exception {
    Connection conn = DriverManager.getConnection(config().getString("url"));
    for (String sql : SQL) {
      System.out.println("Executing: "  + sql);
      conn.createStatement().execute(sql);
    }
  }

  protected static JsonObject config() {
    return new JsonObject()
      .put("url", "jdbc:hsqldb:mem:test?shutdown=true")
      .put("driver_class", "org.hsqldb.jdbcDriver");
  }

  public static String genSalt() {
    final Random r = new SecureRandom();
    byte[] salt = new byte[32];
    r.nextBytes(salt);
    return PasswordEncoder.base64().encode(salt);
  }

  public static void main(String[] args) {
    String pwd = "sausages";
    String salt = genSalt();
    String hashedPwd = new SaltedHashPasswordStrategy(HASH_ALGORITHM).compute(pwd, Optional.of(salt));
    System.out.printf("('tim', '%s', '%s')\");%n", hashedPwd, salt);
  }

  protected JDBCAuth authProvider;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    authProvider = createProvider();
  }

  protected JDBCAuth createProvider() {
    JDBCClient client = JDBCClient.createNonShared(vertx, config());
    return JDBCAuth.create(client);
  }

  @Override
  protected void tearDown() throws Exception {
    super.tearDown();
  }

  @Test
  public void testAuthenticate() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "tim").put("password", "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      testComplete();
    }));
    await();
  }

  @Test
  public void testAuthenticateFailBadPwd() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "tim").put("password", "eggs");
    authProvider.authenticate(authInfo, onFailure(v -> {
      assertEquals("Invalid username/password", v.getMessage());
      testComplete();
    }));
    await();
  }

  @Test
  public void testAuthenticateFailBadUser() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "blah").put("password", "whatever");
    authProvider.authenticate(authInfo, onFailure(v -> {
      assertEquals("Invalid username/password", v.getMessage());
      testComplete();
    }));
    await();
  }

  @Test
  public void testAuthoriseHasRole() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "tim").put("password", "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      user.isAuthorised("role:dev", onSuccess(has -> {
        assertTrue(has);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testAuthoriseNotHasRole() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "tim").put("password", "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      user.isAuthorised("role:manager", onSuccess(has -> {
        assertFalse(has);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testAuthoriseHasPermission() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "tim").put("password", "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      user.isAuthorised("commit_code", onSuccess(has -> {
        assertTrue(has);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testAuthoriseNotHasPermission() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "tim").put("password", "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      user.isAuthorised("eat_sandwich", onSuccess(has -> {
        assertFalse(has);
        testComplete();
      }));
    }));
    await();
  }
}
