package org.su.plugin.security;

import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.mgt.CachingSecurityManager;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.servlet.ShiroFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.su.plugin.security.realm.SmartCustomRealm;
import org.su.plugin.security.realm.SmartJdbcRealm;

import java.util.LinkedHashSet;
import java.util.Set;

//安全相关过滤器
public class SmartSecurityFilter extends ShiroFilter{
    private static final Logger LOGGER = LoggerFactory.getLogger(SmartSecurityFilter.class);
    @Override
    public void init() throws Exception {
        super.init();
        WebSecurityManager webSecurityManager = super.getSecurityManager();
        //设置Realm，可支持多个Realm，并按照先后顺序用逗号分割
        setRealms(webSecurityManager);
        //设置cache，用于减少数据库查询次数
        setCache(webSecurityManager);
    }

    private void setRealms(WebSecurityManager webSecurityManager){
        //读取su.plugin.security.realms配置
        String securityRealms = SecurityConfig.getRealms();
        if (securityRealms != null){
            //根据逗号进行划分
            String[] securityRealmArray = securityRealms.split(",");
            if (securityRealmArray.length > 0 ){
                //使Realm具备唯一性和顺序性
                Set<Realm> realms = new LinkedHashSet<Realm>();
                for (String securityRealm : securityRealmArray){
                    if (securityRealm.equalsIgnoreCase(SecurityConstant.REALMS_JDBC)){
                        //添加基于JDBC的Realm，需配置相关SQL查询语句
                        addJdbcRealm(realms);
                    }else if(securityRealm.equalsIgnoreCase(SecurityConstant.REALMS_CUSTOM)){
                        //添加基于定制化的Realm，需实现SmartSecurity接口
                        addCustomRealm(realms);
                    }
                }
                RealmSecurityManager realmSecurityManager = (RealmSecurityManager)webSecurityManager;
                realmSecurityManager.setRealms(realms);//设置Realm
            }
        }
    }

    private void addJdbcRealm(Set<Realm> realms){
        //添加自己实现的基于JDBC的Ream
        SmartJdbcRealm smartJdbcRealm = new SmartJdbcRealm();
        realms.add(smartJdbcRealm);
    }

    //添加自定义realm
    private void addCustomRealm(Set<Realm> realms){
        //读取su.plugin.security.custom.class配置项
        SmartSecurity smartSecurity = SecurityConfig.getSmartSecurity();
        //添加自己实现的Realm（自定义SQL语句）
        SmartCustomRealm smartCustomRealm = new SmartCustomRealm(smartSecurity);
        realms.add(smartCustomRealm);
    }

    private void setCache(WebSecurityManager webSecurityManager){
        //读取su.plugin.security.cache配置项
        if (SecurityConfig.isCache()){
            CachingSecurityManager cachingSecurityManager = (CachingSecurityManager)webSecurityManager;
            //使用基于内存的cacheManager
            CacheManager cacheManager = new MemoryConstrainedCacheManager();
            cachingSecurityManager.setCacheManager(cacheManager);
        }
    }
}
