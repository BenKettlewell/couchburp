/* Component of CouchDB collaboration plugin for Burp Suite Professional Edition
 * Author: William Patrick Herrin 
 * Date: Jun 20, 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 */
package com.prevsec.couchburp;

import java.net.URL;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.persistence.EntityExistsException;

import org.json.JSONException;
import org.json.JSONObject;

import com.mashape.unirest.http.HttpMethod;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

public class CouchClient {
	private Logger log = Logger.getLogger(this.getClass().getName());
	private URL url;

	private String rootmessage;
	private String connectmessage;
	private UUIDManager uuidManager;

	public void init() {
		rootmessage = "Json error. Are you sure this is the root directory of a CouchDB instance at: " + url.toString()
				+ "?";
		connectmessage = "Unable to establish HTTP connection with: " + url.toString();
	}

	public CouchClient(URL url) throws UnirestException, JSONException, Exception {
		this.url = url;
		init();
		if (!testConnection()) {
			String error = "Unable to create CouchClient";
			log.severe(error);
			throw new Exception(error);
		}
		uuidManager = new UUIDManager(url);
	}

	public boolean testConnection() throws UnirestException, JSONException {
		try {
			return Unirest.get(url.toString()).asJson().getBody().getObject().getString("couchdb").equals("Welcome");
		} catch (UnirestException e) {
			log.log(Level.SEVERE, connectmessage);
			throw new UnirestException(connectmessage);
		} catch (JSONException e) {
			log.log(Level.SEVERE, rootmessage);
			throw new JSONException(rootmessage);
		}
	}

	public void createDB(String name) throws EntityExistsException, UnirestException {
		actionDB(HttpMethod.PUT, name);
	}

	private String parseError(JSONObject response) {
		return "error: " + response.getString("error") + "\nreason:" + response.getString("reason");
	}

	public void deleteDB(String name) throws EntityExistsException, UnirestException {
		actionDB(HttpMethod.DELETE, name);
	}

	private void actionDB(HttpMethod method, String name) throws EntityExistsException, UnirestException {
		try {
			JSONObject response = new JSONObject();
			switch (method) {
			case PUT:
				response = Unirest.put(url + name).asJson().getBody().getObject();
				break;
			case DELETE:
				response = Unirest.delete(url + name).asJson().getBody().getObject();
				break;
			}
			if (!response.optBoolean("ok")) {
				String error = parseError(response);
				log.warning(error);
				throw new EntityExistsException(error);
			}
		} catch (UnirestException e) {
			log.severe(connectmessage);
			throw new UnirestException(connectmessage);
		}
	}
/*
	public DBDescriptor addDatabaseDescriptor(String database, DBDescriptor descriptor) {
		try {
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			JsonAdapter.mashall(descriptor, os);
			JSONObject response = Unirest.put(url.toString() + database + "/root").body(os.toByteArray()).asJson()
					.getBody().getObject();
			if (!response.optString("error").isEmpty() && response.optString("error").equals("conflict")) {
				return Optional.of(Unirest.get(url.toString() + database + "/root").asJson().getBody().getObject().getString("_rev"));
			}
			if (!response.optBoolean("ok")) {
				String error = parseError(response);
				log.warning(error);
				throw new JSONException(error);
			}
			descriptor.setRevision(response.getString("_rev"));
		} catch (UnirestException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JAXBException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;

	}
	
	public Optional<String> checkConflict(){
		
	}
*/
	public synchronized String getUUID() throws Exception {
		try {
			return uuidManager.getUUID();
		} catch (JSONException | InterruptedException | ExecutionException e) {
			// This really shouldn't happen.... but.... stuff happens
			String message = "Connection error getting new UUID";
			log.severe(message);
			throw new Exception(message);
		}
	}
}