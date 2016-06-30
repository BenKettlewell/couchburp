package burp;

/*******************************************************************************
 * Author: William Patrick Herrin 
 * Date: 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 *******************************************************************************/
/**
 * This interface is used for an
 * <code>IHttpRequestResponse</code> object whose request and response messages
 * have been saved to temporary files using
 * <code>IBurpExtenderCallbacks.saveBuffersToTempFiles()</code>.
 */
public interface IHttpRequestResponsePersisted extends IHttpRequestResponse
{
    /**
     * This method is deprecated and no longer performs any action.
     */
    @Deprecated
    void deleteTempFiles();
}
