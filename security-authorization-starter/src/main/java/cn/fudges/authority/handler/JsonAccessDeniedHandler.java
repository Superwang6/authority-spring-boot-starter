package cn.fudges.authority.handler;

import cn.fudges.common.result.ResultCodeEnum;
import cn.fudges.common.result.ResultResponse;
import com.alibaba.fastjson.JSON;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * @author 王平远
 * @since 2025/3/13
 */
public class JsonAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpStatus.OK.value());
        ResultResponse<Object> fail = ResultResponse.fail(ResultCodeEnum.PERMISSION_DENIED.getCode(), ResultCodeEnum.PERMISSION_DENIED.getMessage(), null);
        PrintWriter writer = response.getWriter();
        writer.write(JSON.toJSONString(fail));
        writer.flush();
        writer.close();
    }
}
