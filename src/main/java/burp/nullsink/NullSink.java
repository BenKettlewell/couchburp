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
package burp.nullsink;

import java.awt.Component;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;

public class NullSink implements IHttpRequestResponse, IMessageEditor {

	public NullSink() {
	}

	@Override
	public Component getComponent() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setMessage(byte[] message, boolean isRequest) {
		// TODO Auto-generated method stub

	}

	@Override
	public byte[] getMessage() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isMessageModified() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public byte[] getSelectedData() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] getRequest() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setRequest(byte[] message) {
		// TODO Auto-generated method stub

	}

	@Override
	public byte[] getResponse() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setResponse(byte[] message) {
		// TODO Auto-generated method stub

	}

	@Override
	public String getComment() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setComment(String comment) {
		// TODO Auto-generated method stub

	}

	@Override
	public String getHighlight() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setHighlight(String color) {
		// TODO Auto-generated method stub

	}

	@Override
	public IHttpService getHttpService() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setHttpService(IHttpService httpService) {
		// TODO Auto-generated method stub

	}

}
