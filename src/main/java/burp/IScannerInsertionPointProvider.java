package burp;

/*******************************************************************************
 * Author: William Patrick Herrin 
 * Date: 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 *******************************************************************************/
import java.util.List;

/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerScannerInsertionPointProvider()</code>
 * to register a factory for custom Scanner insertion points.
 */
public interface IScannerInsertionPointProvider
{
    /**
     * When a request is actively scanned, the Scanner will invoke this method,
     * and the provider should provide a list of custom insertion points that
     * will be used in the scan. <b>Note:</b> these insertion points are used in
     * addition to those that are derived from Burp Scanner's configuration, and
     * those provided by any other Burp extensions.
     *
     * @param baseRequestResponse The base request that will be actively
     * scanned.
     * @return A list of
     * <code>IScannerInsertionPoint</code> objects that should be used in the
     * scanning, or
     * <code>null</code> if no custom insertion points are applicable for this
     * request.
     */
    List<IScannerInsertionPoint> getInsertionPoints(
            IHttpRequestResponse baseRequestResponse);
}
