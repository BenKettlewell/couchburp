package burp;

/*******************************************************************************
 * Author: William Patrick Herrin 
 * Date: 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 *******************************************************************************/
import java.awt.Component;

/**
 * This interface is used to provide Burp with details of a custom tab that will
 * be added to Burp's UI, using a method such as
 * <code>IBurpExtenderCallbacks.addSuiteTab()</code>.
 */
public interface ITab
{
    /**
     * Burp uses this method to obtain the caption that should appear on the
     * custom tab when it is displayed.
     *
     * @return The caption that should appear on the custom tab when it is
     * displayed.
     */
    String getTabCaption();

    /**
     * Burp uses this method to obtain the component that should be used as the
     * contents of the custom tab when it is displayed.
     *
     * @return The component that should be used as the contents of the custom
     * tab when it is displayed.
     */
    Component getUiComponent();
}
