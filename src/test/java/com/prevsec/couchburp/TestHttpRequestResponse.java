/* Component of CouchDB collaboration plugin for Burp Suite Professional Edition
 * Author: William Patrick Herrin 
 * Date: Jun 20, 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 */
package com.prevsec.couchburp;

import com.prevsec.couchburp.burp.jaxbjson.HttpService;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class TestHttpRequestResponse implements IHttpRequestResponse {

	private byte[] request;
	private byte[] response;
	private String comment;
	private String color;
	private String highlight;
	private HttpService httpservice;

	public byte[] getRequest() {
		return request;
	}

	public void setRequest(byte[] message) {
		this.request = message;
	}

	public byte[] getResponse() {
		return response;
	}

	public void setResponse(byte[] message) {
		this.response = message;
	}

	public String getComment() {
		return comment;
	}

	public void setComment(String comment) {
		this.comment = comment;
	}

	public String getHighlight() {
		return highlight;
	}

	public void setHighlight(String color) {
		this.color = color;
	}

	public IHttpService getHttpService() {
		return httpservice;
	}

	public void setHttpService(IHttpService httpService) {
		this.httpservice = httpservice;
	}

}
