/* Component of CouchDB collaboration plugin for Burp Suite Professional Edition
 * Author: William Patrick Herrin 
 * Date: Jun 20, 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 */
package com.prevsec.couchburp.burp.jaxbjson;

import com.prevsec.couchburp.models.OWASPCategory;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class HttpRequestResponse implements IHttpRequestResponse {

	// This is shit for couchdb here
	private String uuid;
	private String revision;
	private OWASPCategory category;
	private String parentuuid;

	// Burp stuff here
	private byte[] request;
	private byte[] response;
	private String comment;
	private String color;
	private String highlight;
	private HttpService httpservice;

	// Couchdb stuff
	public String getUUID() {
		return uuid;
	}

	public void setUUID(String uuid) {
		this.uuid = uuid;
	}

	public void setCategory(OWASPCategory category) {
		this.category = category;
	}

	public OWASPCategory getCategory() {
		return category != null ? category : (category = OWASPCategory.UNDEFINED);
	}

	public void setCategory(String category) {
		this.category = OWASPCategory.valueOf(category);
	}

	public String getCategoryAsString() {
		return category != null ? category.toString() : (category = OWASPCategory.UNDEFINED).toString();
	}

	public String getParentUuid() {
		return parentuuid;
	}

	public void setParentUuid(String parentuuid) {
		this.parentuuid = parentuuid;
	}

	// This is stuff for burp below
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