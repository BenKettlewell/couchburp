package com.prevsec.couchburp.burp.jaxbjson;

import burp.IHttpService;

public class HttpService implements IHttpService {

	private String host;
	private int port;
	private String protocol;

	public String getHost() {
		return host;
	}

	public int getPort() {
		return port;
	}

	public String getProtocol() {
		return protocol;
	}

}
