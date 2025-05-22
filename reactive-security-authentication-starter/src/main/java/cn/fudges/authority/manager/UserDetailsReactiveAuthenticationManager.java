package cn.fudges.authority.manager;

import cn.fudges.authority.modes.UserDetail;
import cn.fudges.authority.service.UserService;
import cn.fudges.authority.token.SecurityUsernamePasswordAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.security.authentication.password.CompromisedPasswordException;
import org.springframework.security.authentication.password.ReactiveCompromisedPasswordChecker;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

/**
 * @author 王平远
 * @since 2025/3/17
 */
@ComponentScan
@RequiredArgsConstructor
public class UserDetailsReactiveAuthenticationManager extends AbstractUserDetailsReactiveAuthenticationManager {

    private final UserService userService;

    private final PasswordEncoder passwordEncoder;

    private final Scheduler scheduler = Schedulers.boundedElastic();

    private final UserDetailsChecker preAuthenticationChecks = this::defaultPreAuthenticationChecks;

    private final UserDetailsChecker postAuthenticationChecks = this::defaultPostAuthenticationChecks;

    private ReactiveCompromisedPasswordChecker compromisedPasswordChecker;

    private void defaultPreAuthenticationChecks(UserDetails user) {
        if (!user.isAccountNonLocked()) {
            this.logger.debug("User account is locked");
            throw new LockedException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.locked",
                    "User account is locked"));
        }
        if (!user.isEnabled()) {
            this.logger.debug("User account is disabled");
            throw new DisabledException(
                    this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.disabled", "User is disabled"));
        }
        if (!user.isAccountNonExpired()) {
            this.logger.debug("User account is expired");
            throw new AccountExpiredException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.expired", "User account has expired"));
        }
    }

    private void defaultPostAuthenticationChecks(UserDetails user) {
        if (!user.isCredentialsNonExpired()) {
            this.logger.debug("User account credentials have expired");
            throw new CredentialsExpiredException(this.messages.getMessage(
                    "AbstractUserDetailsAuthenticationProvider.credentialsExpired", "User credentials have expired"));
        }
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String username = authentication.getName();
        String presentedPassword = (String) authentication.getCredentials();

        Integer platform = null;
        if(authentication instanceof SecurityUsernamePasswordAuthenticationToken token) {
            platform = token.getPlatform();
        }

        return queryUser(username, platform)
                .doOnNext(this.preAuthenticationChecks::check)
                .publishOn(this.scheduler)
                .filter((userDetails) -> this.passwordEncoder.matches(presentedPassword, userDetails.getPassword()))
                .switchIfEmpty(Mono.defer(() -> Mono.error(new BadCredentialsException("Invalid Credentials"))))
                .flatMap((userDetails) -> checkCompromisedPassword(presentedPassword).thenReturn(userDetails))
                .doOnNext(this.postAuthenticationChecks::check)
                .map(this::createUsernamePasswordAuthenticationToken);
    }

    private Mono<Void> checkCompromisedPassword(String password) {
        if (this.compromisedPasswordChecker == null) {
            return Mono.empty();
        }
        return this.compromisedPasswordChecker.check(password)
                .filter(CompromisedPasswordDecision::isCompromised)
                .flatMap((compromised) -> Mono.error(new CompromisedPasswordException(
                        "The provided password is compromised, please change your password")));
    }

    private SecurityUsernamePasswordAuthenticationToken createUsernamePasswordAuthenticationToken(UserDetails userDetails) {
        Integer platform = 0;
        if(userDetails instanceof UserDetail user) {
            platform = user.getPlatform();
        }
        return new SecurityUsernamePasswordAuthenticationToken(userDetails,userDetails.getPassword(),userDetails.getAuthorities(),platform);
    }

    @Override
    protected Mono<UserDetails> retrieveUser(String username) {
        return null;
    }


    private Mono<UserDetails> queryUser(String username, Integer platform) {
        return userService.queryUserByUsernameReactive(username, platform);
    }
}
