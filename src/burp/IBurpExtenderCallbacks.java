package burp;

import java.awt.Component;
import java.net.URL;
import java.util.List;

public interface IBurpExtenderCallbacks {
    void setExtensionName(String name);
    void printOutput(String output);
    void printError(String error);
    void registerScannerCheck(IScannerCheck check);
    void addSuiteTab(ITab tab);
    void customizeUiComponent(Component component);
    IExtensionHelpers getHelpers();
    String loadExtensionSetting(String name);
    void saveExtensionSetting(String name, String value);
    
    // ADDED: Scope checking method for "Scope Only" feature
    boolean isInScope(URL url);
} 