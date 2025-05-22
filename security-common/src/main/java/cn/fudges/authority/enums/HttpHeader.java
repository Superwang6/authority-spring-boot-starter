package cn.fudges.authority.enums;

/**
 * @author 王平远
 * @since 2025/3/17
 */
public enum HttpHeader {

    META_DATA("Meta-Data");

    private final String value;

    HttpHeader(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

}
