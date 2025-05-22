package cn.fudges.authority.filter;

import cn.fudges.authority.modes.UserDetail;
import cn.fudges.common.constants.AESKeys;
import cn.fudges.common.constants.CommonRedisKey;
import cn.fudges.common.enums.RequestEnum;
import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.NumberUtil;
import cn.hutool.core.util.ObjectUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * @author 王平远
 * @since 2025/4/25
 */
@RequiredArgsConstructor
public class AuthorizationFilter extends OncePerRequestFilter {

    private final RedissonClient redissonClient;

    private static final SymmetricCrypto USER_ASE = SecureUtil.aes(Base64.decode(AESKeys.USER_ID_KEY));

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String headerUserId = request.getHeader(RequestEnum.USER_ID);
        if(StrUtil.isNotBlank(headerUserId)) {
            String userIdStr = USER_ASE.decryptStr(headerUserId);
            if(StrUtil.isNotBlank(userIdStr) && NumberUtil.isLong(userIdStr)) {
                long userId = Long.parseLong(userIdStr);
                RBucket<UserDetail> bucket = redissonClient.getBucket(CommonRedisKey.USER_LOGIN_USER_DETAIL_PREFIX + userId);
                if(bucket.isExists()) {
                    UserDetail userDetail = bucket.get();
                    if(ObjectUtil.isNotNull(userDetail)) {
                        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                                userDetail, userDetail.getPassword(), userDetail.getAuthorities());
                        SecurityContextHolder.getContext().setAuthentication(token);
                    }
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
