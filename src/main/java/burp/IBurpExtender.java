package burp;

/*******************************************************************************
 * Author: William Patrick Herrin 
 * Date: 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 *******************************************************************************/
/**
 * All extensions must implement this interface.
 *
 * Implementations must be called BurpExtender, in the package burp, must be
 * declared public, and must provide a default (public, no-argument)
 * constructor.
 */
public interface IBurpExtender
{
    /**
     * This method is invoked when the extension is loaded. It registers an
     * instance of the
     * <code>IBurpExtenderCallbacks</code> interface, providing methods that may
     * be invoked by the extension to perform various actions.
     *
     * @param callbacks An
     * <code>IBurpExtenderCallbacks</code> object.
     */
    void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks);
}
