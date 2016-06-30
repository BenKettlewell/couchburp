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
package com.prevsec.couchburp.burp.jaxbjson;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
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

	public HttpRequestResponse(OWASPCategory category, String parentuuid, byte[] request, byte[] response,
			String comment, String color, String highlight, HttpService httpservice) {
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
			System.out.println("_id");
			uuid = json.get("_id") != null ? json.get("_id").getAsString() : null;
			System.out.println("rev");
			revision = json.get("_rev") != null ? json.get("_rev").getAsString() : null;
			System.out.println("service");
			if (json.getAsJsonObject("service") != null) {
				System.out.println("service");
				JsonObject service = json.getAsJsonObject("service");
				System.out.println("host");
				String host = service.get("host") != null ? service.get("host").getAsString() : null;
				System.out.println("port");
				int port = service.get("port") != null ? service.get("port").getAsInt() : null;
				System.out.println("protocol");
				String protocol = service.get("protocol") != null ? service.get("protocol").getAsString() : null;
				httpservice = new HttpService(host, port, protocol);
			}
			System.out.println("category");
			setCategory(json.get("category") != null ? json.get("category").getAsString() : null);
			System.out.println("parent");
			parentuuid = json.get("parent") != null ? json.get("parent").getAsString() : null;
			System.out.println("request");
			request = json.get("request") != null ? json.get("request").getAsString().getBytes() : null;
			System.out.println("response");
			response = json.get("response") != null ? json.get("response").getAsString().getBytes() : null;
			System.out.println("color");
			color = json.get("color") != null ? json.get("color").getAsString() : null;
			System.out.println("highlight");
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

	public JsonObject toJson() {
		JsonObject json = new JsonObject();
		if (uuid != null && revision != null) {
			json.addProperty("_id", getUUID());
			json.addProperty("_rev", getRevision());
		}
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