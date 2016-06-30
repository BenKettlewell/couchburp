package burp;

/*******************************************************************************
 * Author: William Patrick Herrin 
 * Date: 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 *******************************************************************************/

import javax.swing.JMenuItem;
import java.util.List;

/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerContextMenuFactory()</code> to register
 * a factory for custom context menu items.
 */
public interface IContextMenuFactory
{
    /**
     * This method will be called by Burp when the user invokes a context menu
     * anywhere within Burp. The factory can then provide any custom context
     * menu items that should be displayed in the context menu, based on the
     * details of the menu invocation.
     *
     * @param invocation An object that implements the
     * <code>IMessageEditorTabFactory</code> interface, which the extension can
     * query to obtain details of the context menu invocation.
     * @return A list of custom menu items (which may include sub-menus,
     * checkbox menu items, etc.) that should be displayed. Extensions may
     * return
     * <code>null</code> from this method, to indicate that no menu items are
     * required.
     */
    List<JMenuItem> createMenuItems(IContextMenuInvocation invocation);
}
