/* Component of CouchDB collaboration plugin for Burp Suite Professional Edition
 * Author: William Patrick Herrin 
 * Date: Jun 20, 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 */
import javax.xml.bind.JAXBException;

import com.prevsec.couchburp.controller.BurpController;
import com.prevsec.couchburp.ui.BurpFrame;

public class Main {
	public static void main(String[] args) throws JAXBException {
		BurpController controller = new BurpController(null, false);
		BurpFrame frame = new BurpFrame(controller, false);
		frame.setVisible(true);
	}

}
