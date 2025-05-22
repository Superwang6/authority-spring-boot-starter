package cn.fudges.authority.service;

import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.publisher.Mono;

/**
 * @author 王平远
 * @since 2025/3/12
 */

public interface UserService extends ReactiveUserDetailsService {
    Mono<UserDetails> queryUserByUsernameReactive(String username, Integer platform);
}
