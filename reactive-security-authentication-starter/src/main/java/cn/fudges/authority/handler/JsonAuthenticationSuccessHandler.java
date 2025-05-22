package cn.fudges.authority.handler;

import cn.fudges.authority.modes.UserDetail;
import cn.fudges.common.constants.AESKeys;
import cn.fudges.common.constants.CommonRedisKey;
import cn.fudges.common.result.ResultResponse;
import cn.hutool.core.codec.Base64;
import cn.hutool.core.lang.Dict;
import cn.hutool.core.util.IdUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import com.alibaba.fastjson.JSON;
import lombok.RequiredArgsConstructor;
import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * @author 王平远
 * @since 2025/3/13
 */
@Component
@RequiredArgsConstructor
public class JsonAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {

    private final RedissonClient redissonClient;

    private static final SymmetricCrypto AES = SecureUtil.aes(Base64.decode(AESKeys.AUTHORIZATION_KEY));

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange exchange, Authentication authentication) {
        UserDetail userDetail = (UserDetail) authentication.getPrincipal();

        String token;
        // 存入userid -> 用户信息映射
        RBucket<UserDetail> bucket = redissonClient.getBucket(CommonRedisKey.USER_LOGIN_USER_DETAIL_PREFIX + userDetail.getId());
        RBucket<String> userBucket = redissonClient.getBucket(CommonRedisKey.USER_LOGIN_USER_TOKEN_PREFIX + userDetail.getId());
        if (bucket.isExists()) {
            // 如果之前登陆过则延长登录时间
            UserDetail userDetail1 = bucket.get();
            bucket.expire(Duration.ofDays(10));
            userBucket.expire(Duration.ofDays(10));

            token = userBucket.get();
        } else {
            bucket.set(userDetail, Duration.ofDays(10));

            token = AES.encryptHex(userDetail.getId() + ":" + IdUtil.simpleUUID());
            userBucket.set(token, Duration.ofDays(10));
        }

        ResultResponse<?> res = ResultResponse.success(
                Dict.create().set("id", userDetail.getId()).set("nickName", userDetail.getNickName()).set("mobilePhone", userDetail.getMobilePhone()).set("tenantId", userDetail.getTenantId()).set("platform", userDetail.getPlatform()).set("authorityIdList", userDetail.getAuthorityIdList()).set("authorization", token)
        );

        ServerHttpResponse response = exchange.getExchange().getResponse();
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.setStatusCode(HttpStatus.OK);
        return response.writeWith(Mono.fromSupplier(() -> response.bufferFactory().wrap(JSON.toJSONBytes(res))));
    }
}
