package org.su.plugin.security;

import org.su.framework.helper.ConfigHelper;
import org.su.framework.util.ReflectionUtil;

//从配置文件中获取相关属性
public final class SecurityConfig {
    public static String getRealms(){
        return ConfigHelper.getString(SecurityConstant.REALMS);
    }

    //获取jdbc相关验证配置
    public static String getJdbcAuthcQuery(){
        return ConfigHelper.getString(SecurityConstant.JDBC_AUTHC_QUERY);
    }
    //获取jdbc角色配置
    public static String getJdbcRolesQuery(){
        return ConfigHelper.getString(SecurityConstant.JDBC_ROLES_QUERY);
    }
    //获取jdbc权限配置
    public static String getJdbcPermissionQuery(){
        return ConfigHelper.getString(SecurityConstant.JDBC_PERMISSIONS_QUERY);
    }
    //获取是否缓存
    public static boolean isCache(){
        return ConfigHelper.getBoolean(SecurityConstant.CACHE);
    }

    //获取安全配置
    public static SmartSecurity getSmartSecurity(){
        String className = ConfigHelper.getString(SecurityConstant.SMART_SECURITY);
        return (SmartSecurity) ReflectionUtil.newInstance(className);
    }
}
