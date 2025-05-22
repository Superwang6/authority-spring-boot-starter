package cn.fudges.authority.utils;

import cn.fudges.authority.enums.HttpHeader;
import cn.hutool.core.util.ObjectUtil;
import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.http.HttpHeaders;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;


/**
 * @author 王平远
 * @since 2025/3/17
 */

public class HeaderUtils {

    public static String getMetaData(ServerWebExchange exchange, String key) {
        HttpHeaders headers = exchange.getRequest().getHeaders();
        String metaDataStr = headers.getFirst(HttpHeader.META_DATA.getValue());
        if(!StrUtil.hasBlank(metaDataStr)) {
            JSONObject metaData = JSON.parseObject(metaDataStr);
            if(ObjectUtil.isNotNull(metaData) && StringUtils.hasText(key)) {
                return metaData.getString(key);
            }
        }
        return null;
    }
}
