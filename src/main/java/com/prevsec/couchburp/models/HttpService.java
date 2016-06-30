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
package com.prevsec.couchburp.models;

import com.google.gson.JsonObject;

import burp.IHttpService;

public class HttpService implements IHttpService {

	private String host;
	private int port;
	private String protocol;

	public HttpService(String host, int port, String protocol) {
		this.host = host;
		this.port = port;
		this.protocol = protocol;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public String getHost() {
		return host;
	}

	public int getPort() {
		return port;
	}

	public String getProtocol() {
		return protocol;
	}

	public JsonObject toJsonObject() {
		JsonObject json = new JsonObject();
		json.addProperty("host", getHost());
		json.addProperty("port", getPort());
		json.addProperty("protocol", getProtocol());
		return json;
	}

}
