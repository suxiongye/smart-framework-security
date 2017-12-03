package org.su.plugin.security.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.su.plugin.security.SecurityConstant;
import org.su.plugin.security.SmartSecurity;
import org.su.plugin.security.password.Md5CredentialsMatcher;

import java.util.HashSet;
import java.util.Set;

//基于smart的自定义realm，需要实现smartSecurity接口
public class SmartCustomRealm extends AuthorizingRealm {
    private final SmartSecurity smartSecurity;

    public SmartCustomRealm(SmartSecurity smartSecurity) {
        this.smartSecurity = smartSecurity;
        super.setName(SecurityConstant.REALMS_CUSTOM);
        super.setCredentialsMatcher(new Md5CredentialsMatcher());
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        if (token == null) {
            throw new AuthenticationException("parameter token is null");
        }
        //通过authenticationToken对象获取从表单中提交过来的用户名
        String username = ((UsernamePasswordToken) token).getUsername();
        //通过SmartSecurity接口并根据用户名获取数据库中存放的密码
        String password = smartSecurity.getPassword(username);
        //将用户名和密码放入authenticationInfo对象中
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo();
        authenticationInfo.setPrincipals(new SimplePrincipalCollection(username, super.getName()));
        authenticationInfo.setCredentials(password);
        return authenticationInfo;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        if (principals == null){
            throw new AuthorizationException("parameter principals is null");
        }
        //获取已认证用户的用户名
        String username = (String)super.getAvailablePrincipal(principals);
        //通过smartSecurity接口，根据用户名获取角色名集合
        Set<String> roleNameSet = smartSecurity.getRoleNameSet(username);
        //通过SmartSecurity接口，根据角色名与对应权限名集合
        Set<String> permissionNameSet = new HashSet<String>();
        if (roleNameSet != null && roleNameSet.size() > 0){
            for (String roleName :roleNameSet){
                Set<String> currentPermissionNameSet = smartSecurity.getPermissionNameSet(roleName);
                permissionNameSet.addAll(currentPermissionNameSet);
            }
        }

        //将角色名集合与权限名集合放入authorizationInfo中，便于后续授权
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.setRoles(roleNameSet);
        simpleAuthorizationInfo.setStringPermissions(permissionNameSet);
        return simpleAuthorizationInfo;
    }
}
