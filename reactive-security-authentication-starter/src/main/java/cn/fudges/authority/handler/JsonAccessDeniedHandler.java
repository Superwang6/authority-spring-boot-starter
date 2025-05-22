package cn.fudges.authority.handler;

import cn.fudges.common.result.ResultCodeEnum;
import cn.fudges.common.result.ResultResponse;
import com.alibaba.fastjson.JSON;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * @author 王平远
 * @since 2025/3/13
 */
public class JsonAccessDeniedHandler implements ServerAccessDeniedHandler {


    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.setStatusCode(HttpStatus.OK);
        ResultResponse<Object> fail = ResultResponse.fail(ResultCodeEnum.PERMISSION_DENIED.getCode(), ResultCodeEnum.PERMISSION_DENIED.getMessage(), null);
        return response.writeWith(Mono.fromSupplier(() -> response.bufferFactory().wrap(JSON.toJSONBytes(fail))));
    }
}
