package burp;

/*******************************************************************************
 * Author: William Patrick Herrin 
 * Date: 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 *******************************************************************************/
/**
 * This interface is used to hold details about an Intruder attack.
 */
public interface IIntruderAttack 
{
    /**
     * This method is used to retrieve the HTTP service for the attack.
     * 
     * @return The HTTP service for the attack.
     */
    IHttpService getHttpService();
    
    /**
     * This method is used to retrieve the request template for the attack.
     * 
     * @return The request template for the attack.
     */
    byte[] getRequestTemplate();
    
}
