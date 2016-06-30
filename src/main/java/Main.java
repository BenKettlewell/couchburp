
/*******************************************************************************
 * Author: William Patrick Herrin 
 * Date: 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 *******************************************************************************/
/* Component of CouchDB collaboration plugin for Burp Suite Professional Edition
 * Author: William Patrick Herrin 
 * Date: Jun 20, 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 */
import java.util.logging.Logger;

import javax.swing.JFrame;
import javax.swing.JWindow;
import javax.swing.SwingUtilities;
import javax.xml.bind.JAXBException;

import com.prevsec.couchburp.controller.BurpController;
import com.prevsec.couchburp.ui.BurpFrame;

public class Main {
	public static void main(String[] args) throws JAXBException {

		SwingUtilities.invokeLater(new Runnable() {

			@Override
			public void run() {
				BurpController controller = new BurpController(null, false);
				BurpFrame frame = new BurpFrame(controller, false);
				frame.setVisible(true);
				JFrame jFrame = new JFrame("FUCK");
				jFrame.add(frame);
				jFrame.setVisible(true);
				Logger.getLogger(this.getClass().getName()).info("we reached the end of the runnable");
			}
		});
	}

}
