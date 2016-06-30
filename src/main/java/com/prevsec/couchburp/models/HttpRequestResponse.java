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

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class HttpRequestResponse implements IHttpRequestResponse {

	// This is shit for couchdb here
	private String type = "http";
	private String uuid;
	private String revision;
	private OWASPCategory category;
	private String parentuuid;

	// Burp stuff here
	private String request;
	private String response;
	private String comment;
	private String color;
	private String highlight;
	private HttpService httpservice;

	@Override
	public String toString() {
		return "HttpRequestResponse [uuid=" + uuid + ", revision=" + revision + "]";
	}

	public HttpRequestResponse(OWASPCategory category, String parentuuid, String request, String response,
			String comment, String color, String highlight, IHttpService httpservice) {
		this.category = category;
		this.parentuuid = parentuuid;
		this.request = request;
		this.response = response;
		this.comment = comment;
		this.color = color;
		this.highlight = highlight;
		this.httpservice = new HttpService(httpservice.getHost(), httpservice.getPort(), httpservice.getProtocol());
	}

	public HttpRequestResponse(String uuid, String revision, OWASPCategory category, String parentuuid, String request,
			String response, String comment, String color, String highlight, IHttpService httpservice) {
		this.uuid = uuid;
		this.revision = revision;
		this.category = category;
		this.parentuuid = parentuuid;
		this.request = request;
		this.response = response;
		this.comment = comment;
		this.color = color;
		this.highlight = highlight;
		this.httpservice = new HttpService(httpservice.getHost(), httpservice.getPort(), httpservice.getProtocol());
	}

	public HttpRequestResponse(String uuid, OWASPCategory category, String parentuuid, String request, String response,
			String comment, String color, String highlight, HttpService httpservice) {
		this.uuid = uuid;
		this.category = category;
		this.parentuuid = parentuuid;
		this.request = request;
		this.response = response;
		this.comment = comment;
		this.color = color;
		this.highlight = highlight;
		this.httpservice = httpservice;
	}

	// Contructor from JsonObject
	public HttpRequestResponse(JsonObject json) {
		try {
			uuid = json.get("_id") != null ? json.get("_id").getAsString() : null;
			revision = json.get("_rev") != null ? json.get("_rev").getAsString() : null;
			if (json.getAsJsonObject("service") != null) {
				JsonObject service = json.getAsJsonObject("service");
				String host = service.get("host") != null ? service.get("host").getAsString() : null;
				int port = service.get("port") != null ? service.get("port").getAsInt() : null;
				String protocol = service.get("protocol") != null ? service.get("protocol").getAsString() : null;
				httpservice = new HttpService(host, port, protocol);
			}
			setCategory(json.get("category") != null ? json.get("category").getAsString() : null);
			parentuuid = json.get("parent") != null ? json.get("parent").getAsString() : null;
			request = json.get("request") != null ? json.get("request").getAsString() : null;
			response = json.get("response") != null ? json.get("response").getAsString() : null;
			color = json.get("color") != null ? json.get("color").getAsString() : null;
			highlight = json.get("highlight") != null ? json.get("highlight").getAsString() : null;
		} catch (Exception e) {
			System.out.println(e.getMessage());
			throw e;
		}
	}

	public HttpRequestResponse() {
		// TODO Auto-generated constructor stub
	}

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
		return request.getBytes();
	}

	public void setRequest(byte[] message) {
		this.request = new String(message);
	}

	public byte[] getResponse() {
		return response.getBytes();
	}

	public void setResponse(byte[] message) {
		this.response = new String(message);
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

	public JsonObject toJson() {
		JsonObject json = new JsonObject();
		if (uuid != null) {
			json.addProperty("_id", getUUID());
		}
		if (revision != null) {
			json.addProperty("_rev", getRevision());
		}
		json.addProperty("type", type);
		json.add("service", httpservice.toJsonObject());
		json.addProperty("category", getCategoryAsString());
		json.addProperty("parent", getParentUuid());
		json.addProperty("request", getRequestAsString());
		json.addProperty("response", getResponseAsString());
		json.addProperty("color", getColor());
		json.addProperty("highlight", getHighlight());
		return json;
	}
	// private byte[] request;
	// private byte[] response;
	// private String comment;
	// private String color;
	// private String highlight;
	// private HttpService httpservice;

	private String getColor() {
		return color;
	}

	private String getRequestAsString() {
		return new String(request);
	}

	private String getResponseAsString() {
		return new String(response);
	}

	public String getRevision() {
		return revision;
	}

	public void setRevision(String rev) {
		this.revision = rev;
	}

}