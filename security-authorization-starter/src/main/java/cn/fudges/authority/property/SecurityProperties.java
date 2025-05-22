package cn.fudges.authority.property;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * @author 王平远
 * @since 2025/4/25
 */
@Component
@ConfigurationProperties(prefix = "cn.fudges.security")
@Data
public class SecurityProperties {
    private List<String> ignoreUrls = new ArrayList<>();
}
