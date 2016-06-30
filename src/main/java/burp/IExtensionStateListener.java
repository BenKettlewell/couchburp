package burp;

/*******************************************************************************
 * Author: William Patrick Herrin 
 * Date: 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 *******************************************************************************/
/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerExtensionStateListener()</code> to
 * register an extension state listener. The listener will be notified of
 * changes to the extension's state. <b>Note:</b> Any extensions that start
 * background threads or open system resources (such as files or database
 * connections) should register a listener and terminate threads / close
 * resources when the extension is unloaded.
 */
public interface IExtensionStateListener
{
    /**
     * This method is called when the extension is unloaded.
     */
    void extensionUnloaded();
}
