package burp;

import java.net.URL;
import java.util.List;

public interface IRequestInfo {
    String getMethod();
    URL getUrl();
    List<String> getHeaders();
    List<IParameter> getParameters();
    byte[] getBody();
    int getBodyOffset();
} 