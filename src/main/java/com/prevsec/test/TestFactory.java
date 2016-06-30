package com.prevsec.test;

import com.prevsec.couchburp.burp.jaxbjson.HttpRequestResponse;
import com.prevsec.couchburp.burp.jaxbjson.HttpService;
import com.prevsec.couchburp.models.OWASPCategory;

public class TestFactory {

	public static HttpRequestResponse createHttpRequestResponse() {
		return new HttpRequestResponse(OWASPCategory.OTGAUTHN001, null,
				"HTTP 1.1 GET /blahblahblah.ok\nNEW LINE STUFF CUT THIS OUT".getBytes(), "200 OK".getBytes(), "Ok",
				"blue?", "yes?", new HttpService("website.com", 443, "https"));

	}

}
