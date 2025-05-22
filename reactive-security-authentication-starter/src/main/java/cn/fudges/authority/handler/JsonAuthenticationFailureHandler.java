package cn.fudges.authority.handler;

import cn.fudges.common.result.ResultCodeEnum;
import cn.fudges.common.result.ResultResponse;
import com.alibaba.fastjson.JSON;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import reactor.core.publisher.Mono;

/**
 * @author 王平远
 * @since 2025/3/13
 */
public class JsonAuthenticationFailureHandler implements ServerAuthenticationFailureHandler {

    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange exchange, AuthenticationException exception) {
        ResultResponse<?> res = ResultResponse.fail(ResultCodeEnum.ACCOUNT_PASSWORD_ERROR.getCode(), ResultCodeEnum.ACCOUNT_PASSWORD_ERROR.getMessage(), null);
        ServerHttpResponse response = exchange.getExchange().getResponse();
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.setStatusCode(HttpStatus.OK);
        return response.writeWith(Mono.fromSupplier(() -> response.bufferFactory().wrap(JSON.toJSONBytes(res))));
    }
}
