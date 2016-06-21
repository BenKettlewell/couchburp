/* Component of CouchDB collaboration plugin for Burp Suite Professional Edition
 * Author: William Patrick Herrin 
 * Date: Jun 20, 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 */
package com.prevsec.couchburp;

import java.net.URL;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.json.JSONArray;
import org.json.JSONException;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;

public class UUIDManager {
	public Queue<String> uuids = new LinkedList<String>();
	private URL url;
	private boolean getting = false;

	public UUIDManager(URL url) {
		this.url = url;
	}

	public synchronized String getUUID() throws JSONException, InterruptedException, ExecutionException {
		boolean more = true;
		if (uuids.isEmpty()) {
			more = getMore();
			while (more) {
			}
		}
		return uuids.poll();
	}

	private synchronized boolean getMore() throws JSONException, InterruptedException, ExecutionException {
		Future<HttpResponse<JsonNode>> future = Unirest.get(url.toString() + "_uuids").queryString("count", 100)
				.asJsonAsync();
		JSONArray uuidArray = future.get().getBody().getObject().getJSONArray("uuids");

		for (int i = 0; i < uuidArray.length(); i++) {
			uuids.add(uuidArray.getString((i)));
		}
		return false;
	}
}
