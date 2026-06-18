package burp;

import java.util.List;
import java.net.URL;

public interface IExtensionHelpers {
    IRequestInfo analyzeRequest(byte[] request);
    IRequestInfo analyzeRequest(IHttpRequestResponse request);
    IResponseInfo analyzeResponse(byte[] response);
    List<IParameter> getParameters(byte[] request);
    String urlEncode(String data);
    String urlDecode(String data);
    int indexOf(byte[] data, byte[] pattern, boolean caseSensitive, int from, int to);
    IParameter buildParameter(String name, String value, byte type);
    byte[] updateParameter(byte[] request, IParameter parameter);
    byte[] buildHttpMessage(List<String> headers, byte[] body);
    String bytesToString(byte[] data);
    byte[] stringToBytes(String data);
}