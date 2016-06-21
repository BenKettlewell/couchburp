/* Component of CouchDB collaboration plugin for Burp Suite Professional Edition
 * Author: William Patrick Herrin 
 * Date: Jun 20, 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 */
package burp;

import java.awt.Component;

import javax.swing.SwingUtilities;

import com.prevsec.couchburp.controller.BurpController;
import com.prevsec.couchburp.ui.BurpFrame;

public class BurpExtender implements IBurpExtender, ITab {

	private BurpController controller;
	private BurpFrame frame;
	private IBurpExtenderCallbacks callbacks;

	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		controller = new BurpController(callbacks, true);
		callbacks.setExtensionName("Couch Burp");
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				frame = new BurpFrame(controller, true);
				callbacks.customizeUiComponent(frame);
				callbacks.addSuiteTab(BurpExtender.this);
			}
		});
	}

	@Override
	public String getTabCaption() {
		return "Couch Burp";
	}

	@Override
	public Component getUiComponent() {
		return frame;
	}
}