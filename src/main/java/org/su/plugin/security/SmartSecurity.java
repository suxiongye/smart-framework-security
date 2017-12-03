package org.su.plugin.security;

import java.util.Set;

//安全接口，可以配置自定义权限控制方式
public interface SmartSecurity {
    //根据用户名获取密码
    String getPassword(String username);

    //根据用户名获取角色名集合
    Set<String> getRoleNameSet(String username);

    //根据角色名获取权限名集合
    Set<String> getPermissionNameSet(String roleName);
}
