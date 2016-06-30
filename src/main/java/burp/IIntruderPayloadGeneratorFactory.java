package burp;

/*******************************************************************************
 * Author: William Patrick Herrin 
 * Date: 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 *******************************************************************************/
/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerIntruderPayloadGeneratorFactory()</code>
 * to register a factory for custom Intruder payloads.
 */
public interface IIntruderPayloadGeneratorFactory
{
    /**
     * This method is used by Burp to obtain the name of the payload generator.
     * This will be displayed as an option within the Intruder UI when the user
     * selects to use extension-generated payloads.
     *
     * @return The name of the payload generator.
     */
    String getGeneratorName();

    /**
     * This method is used by Burp when the user starts an Intruder attack that
     * uses this payload generator.
     *
     * @param attack An
     * <code>IIntruderAttack</code> object that can be queried to obtain details
     * about the attack in which the payload generator will be used.
     * @return A new instance of
     * <code>IIntruderPayloadGenerator</code> that will be used to generate
     * payloads for the attack.
     */
    IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack);
}
