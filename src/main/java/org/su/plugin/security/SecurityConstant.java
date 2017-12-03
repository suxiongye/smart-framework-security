package org.su.plugin.security;

//常量接口
public interface SecurityConstant {
    String REALMS = "su.plugin.security.realms";
    String REALMS_JDBC = "jdbc";
    String REALMS_CUSTOM = "custom";

    String SMART_SECURITY = "su.plugin.security.custom.class";

    String JDBC_AUTHC_QUERY = "su.plugin.security.jdbc.authc_query";
    String JDBC_ROLES_QUERY = "su.plugin.security.jdbc.roles_query";
    String JDBC_PERMISSIONS_QUERY = "su.plugin.security.jdbc.permissions_query";

    String CACHE = "su.plugin.security.cache";
}
