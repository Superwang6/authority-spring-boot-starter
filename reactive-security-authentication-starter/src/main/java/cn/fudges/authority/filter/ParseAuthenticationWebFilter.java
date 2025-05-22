package cn.fudges.authority.filter;

import cn.fudges.authority.modes.UserDetail;
import cn.fudges.authority.token.SecurityUsernamePasswordAuthenticationToken;
import cn.fudges.common.constants.AESKeys;
import cn.fudges.common.constants.CommonRedisKey;
import cn.fudges.common.enums.RequestEnum;
import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.NumberUtil;
import cn.hutool.core.util.ObjectUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import lombok.RequiredArgsConstructor;
import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

/**
 * @author 王平远
 * @since 2025/4/8
 */
@Component
@RequiredArgsConstructor
public class ParseAuthenticationWebFilter implements WebFilter {

    private final RedissonClient redissonClient;

    private static final String AUTHORIZATION = "Authorization";

    private static final SymmetricCrypto TOKEN_AES = SecureUtil.aes(Base64.decode(AESKeys.AUTHORIZATION_KEY));
    private static final SymmetricCrypto USER_ASE = SecureUtil.aes(Base64.decode(AESKeys.USER_ID_KEY));

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return createContext(exchange)
                .defaultIfEmpty(Context.empty())
                .flatMap(ctx -> chain.filter(exchange).contextWrite(ctx));
    }

    private Mono<Context> createContext(ServerWebExchange exchange) {
        String authorization = exchange.getRequest().getHeaders().getFirst(AUTHORIZATION);
        if (StrUtil.isBlank(authorization)) {
            return Mono.empty();
        }
        Long userId = null;
        String info = TOKEN_AES.decryptStr(authorization);
        if(StrUtil.isNotBlank(info)) {
            String userIdStr = info.split(":")[0];
            if(NumberUtil.isLong(userIdStr)) {
                userId = Long.valueOf(userIdStr);
            }
        }

        String userKey = CommonRedisKey.USER_LOGIN_USER_DETAIL_PREFIX + userId;
        RBucket<UserDetail> userDetailBucket = redissonClient.getBucket(userKey);
        return Mono.fromCallable(userDetailBucket::get)
                .filter(ObjectUtil::isNotNull)
                .map(detail -> {
                    Long uid = detail.getId();
                    exchange.getRequest().mutate().header(RequestEnum.USER_ID, USER_ASE.encryptHex(uid + ""));

                    SecurityUsernamePasswordAuthenticationToken token = new SecurityUsernamePasswordAuthenticationToken(
                            detail, detail.getPassword(), detail.getAuthorities(), detail.getPlatform());
                    SecurityContextImpl context = new SecurityContextImpl(token);
                    return ReactiveSecurityContextHolder.withSecurityContext(Mono.just(context));
                });
    }
}
