package burp;

import javax.swing.JMenuItem;
import java.util.List;

/**
 * Burp extension context-menu factory (subset of the Burp Extender API).
 */
public interface IContextMenuFactory {
    List<JMenuItem> createMenuItems(IContextMenuInvocation invocation);
}
