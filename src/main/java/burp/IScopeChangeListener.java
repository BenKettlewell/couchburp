package burp;

/*******************************************************************************
 * Author: William Patrick Herrin 
 * Date: 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 *******************************************************************************/
/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerScopeChangeListener()</code> to register
 * a scope change listener. The listener will be notified whenever a change
 * occurs to Burp's suite-wide target scope.
 */
public interface IScopeChangeListener
{
    /**
     * This method is invoked whenever a change occurs to Burp's suite-wide
     * target scope.
     */
    void scopeChanged();
}
