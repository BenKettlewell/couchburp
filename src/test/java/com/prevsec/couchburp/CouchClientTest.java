package com.prevsec.couchburp;

import java.net.URL;

import javax.persistence.EntityExistsException;

import org.json.JSONException;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.runners.MethodSorters;

import com.mashape.unirest.http.exceptions.UnirestException;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CouchClientTest {
	private static CouchClient client;
	private URL url;

	// test variable names
	private static String testDBName = "testdatabase";

	@Rule
	public TestRule watcher = new TestWatcher() {

		protected void starting(Description description) {
			System.out.println("Starting test: " + description.getMethodName() + " {");
		}

		protected void finished(Description description) {
			System.out.println("}");
		}
	};

	@Before
	public void setUp() throws Exception {
		url = new URL("http://localhost:5984/");
		System.out.println(url.toString());
		client = new CouchClient(url);
	}

	@Test
	public void testTestConnection() throws UnirestException {
		client.testConnection();
	}

	@Test(expected = UnirestException.class)
	public void testTestConnectionBadHost() throws Exception {
		client = new CouchClient(new URL("http://localhost:80"));
	}

	@Test(expected = JSONException.class)
	public void testTestConnectionBadDirectory() throws Exception {
		client = new CouchClient(new URL("http://localhost:5984/lakjasdjkhrskjlhdgf3423"));
	}

	@Test
	public void createDB() throws EntityExistsException, UnirestException {
		client.createDB(testDBName);
	}

	@Test(expected = EntityExistsException.class)
	public void createDBExists() throws EntityExistsException, UnirestException {
		client.createDB(testDBName);
	}

	@Test
	public void deleteDB() throws EntityExistsException, UnirestException {
		client.deleteDB(testDBName);
	}

	@Test(expected = EntityExistsException.class)
	public void deleteDBExists() throws EntityExistsException, UnirestException {
		client.deleteDB(testDBName);
	}

	@AfterClass
	public static void cleanUp() {
		try {
			client.deleteDB(testDBName);
		} catch (Exception e) {
		}
	}

}
