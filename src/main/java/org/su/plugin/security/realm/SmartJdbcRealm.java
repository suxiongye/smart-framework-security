package org.su.plugin.security.realm;

import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.su.framework.helper.DatabaseHelper;
import org.su.plugin.security.SecurityConfig;
import org.su.plugin.security.password.Md5CredentialsMatcher;

public class SmartJdbcRealm extends JdbcRealm {
    private static final Logger LOGGER = LoggerFactory.getLogger(SmartJdbcRealm.class);
    public SmartJdbcRealm(){
        super.setDataSource(DatabaseHelper.getDataSource());
        super.setAuthenticationQuery(SecurityConfig.getJdbcAuthcQuery());
        super.setUserRolesQuery(SecurityConfig.getJdbcRolesQuery());
        super.setPermissionsQuery(SecurityConfig.getJdbcPermissionQuery());
        super.setPermissionsLookupEnabled(true);
        //super.setCredentialsMatcher(new Md5CredentialsMatcher());
    }
}
