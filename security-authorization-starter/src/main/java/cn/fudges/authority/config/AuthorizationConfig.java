package cn.fudges.authority.config;

import cn.fudges.authority.filter.AuthorizationFilter;
import org.redisson.api.RedissonClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * 授权配置类
 * @author 王平远
 * @since 2025/4/25
 */
@Configuration
@ComponentScan("cn.fudges.authority")
public class AuthorizationConfig {

    @Bean
    @ConditionalOnBean(RedissonClient.class)
    public AuthorizationFilter authorizationFilter(RedissonClient redissonClient) {
        return new AuthorizationFilter(redissonClient);
    }
}
