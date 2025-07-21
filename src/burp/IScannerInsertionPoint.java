package burp;

public interface IScannerInsertionPoint {
    String getInsertionPointName();
    String getBaseValue();
    byte[] buildRequest(byte[] payload);
    int[] getPayloadOffsets(byte[] payload);
    byte getInsertionPointType();
} 