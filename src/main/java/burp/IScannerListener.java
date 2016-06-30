package burp;

/*******************************************************************************
 * Author: William Patrick Herrin 
 * Date: 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 *******************************************************************************/
/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerScannerListener()</code> to register a
 * Scanner listener. The listener will be notified of new issues that are
 * reported by the Scanner tool. Extensions can perform custom analysis or
 * logging of Scanner issues by registering a Scanner listener.
 */
public interface IScannerListener
{
    /**
     * This method is invoked when a new issue is added to Burp Scanner's
     * results.
     *
     * @param issue An
     * <code>IScanIssue</code> object that the extension can query to obtain
     * details about the new issue.
     */
    void newScanIssue(IScanIssue issue);
}
