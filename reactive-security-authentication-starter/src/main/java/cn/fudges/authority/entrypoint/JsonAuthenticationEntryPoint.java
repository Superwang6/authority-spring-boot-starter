package cn.fudges.authority.entrypoint;

import cn.fudges.common.result.ResultCodeEnum;
import cn.fudges.common.result.ResultResponse;
import com.alibaba.fastjson.JSON;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * @author 王平远
 * @since 2025/3/14
 */

public class JsonAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {
    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.setStatusCode(HttpStatus.OK);
        ResultResponse<Object> fail = ResultResponse.fail(ResultCodeEnum.NO_LOGIN.getCode(), ResultCodeEnum.NO_LOGIN.getMessage(), null);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(JSON.toJSONBytes(fail))));
    }
}
