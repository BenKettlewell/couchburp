package burp;

/*******************************************************************************
 * Author: William Patrick Herrin 
 * Date: 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 *******************************************************************************/
/**
 * This interface is used to hold details of a temporary file that has been
 * created via a call to
 * <code>IBurpExtenderCallbacks.saveToTempFile()</code>.
 *
 */
public interface ITempFile
{
    /**
     * This method is used to retrieve the contents of the buffer that was saved
     * in the temporary file.
     *
     * @return The contents of the buffer that was saved in the temporary file.
     */
    byte[] getBuffer();

    /**
     * This method is deprecated and no longer performs any action.
     */
    @Deprecated
    void delete();
}
