package com.prevsec.test;

import com.prevsec.couchburp.models.HttpRequestResponse;
import com.prevsec.couchburp.models.HttpService;
import com.prevsec.couchburp.models.OWASPCategory;

public class TestFactory {

	public static HttpRequestResponse createHttpRequestResponse() {
		return new HttpRequestResponse(OWASPCategory.OTGAUTHN001, null,
				"HTTP 1.1 GET /blahblahblah.ok\nNEW LINE STUFF CUT THIS OUT", "200 OK", "Ok", "blue?", "yes?",
				new HttpService("website.com", 443, "https"));
	}

	public static HttpRequestResponse createHttpRequestResponse(String id) {
		return new HttpRequestResponse(id, OWASPCategory.OTGAUTHN001, null,
				"HTTP 1.1 GET /blahblahblah.ok\nNEW LINE STUFF CUT THIS OUT", "200 OK", "Ok", "blue?", "yes?",
				new HttpService("website.com", 443, "https"));
	}

	public static HttpRequestResponse createHttpRequestResponse(String id, String revision) {
		return new HttpRequestResponse(id, revision, OWASPCategory.OTGAUTHN001, null,
				"HTTP 1.1 GET /blahblahblah.ok\nNEW LINE STUFF CUT THIS OUT", "200 OK", "Ok", "blue?", "yes?",
				new HttpService("website.com", 443, "https"));
	}
}
