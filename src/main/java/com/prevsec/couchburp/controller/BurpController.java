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
package com.prevsec.couchburp.controller;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonObjectBuilder;
import javax.persistence.EntityExistsException;
import javax.persistence.criteria.From;
import javax.swing.JOptionPane;
import javax.swing.JTree;
import javax.swing.table.TableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.MutableTreeNode;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.lightcouch.Changes;
import org.lightcouch.ChangesResult.Row;
import org.lightcouch.CouchDbClient;
import org.lightcouch.Response;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.mashape.unirest.http.HttpMethod;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import com.prevsec.couchburp.CouchClient;
import com.prevsec.couchburp.UUIDManager;
import com.prevsec.couchburp.burp.jaxbjson.HttpRequestResponse;
import com.prevsec.couchburp.models.BurpTableModel;
import com.prevsec.couchburp.models.OWASPCategory;
import com.prevsec.couchburp.ui.BurpFrame;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.nullsink.NullSink;

public class BurpController implements IMessageEditorController {
	private BurpFrame frame;
	private CouchClient client;
	// This is invisible, so the name is whatever
	private DefaultMutableTreeNode root = new DefaultMutableTreeNode("CouchDB");
	private DefaultTreeModel treeModel = new DefaultTreeModel(root);
	private JTree tree = new JTree(treeModel);
	private IBurpExtenderCallbacks callbacks;
	private IHttpRequestResponse requestResponse;
	private IMessageEditor requestViewer;
	private IMessageEditor responseViewer;
	private boolean isBurp;
	private Logger log = Logger.getLogger(this.getClass().getName());
	private URL url;
	private String rootmessage;
	private String connectmessage;
	private UUIDManager uuidManager;
	private CouchDbClient cdbclient;
	private BurpTableModel tableModel = new BurpTableModel();
	private Executor exec = Executors.newCachedThreadPool();
	private List<HttpRequestResponse> tryLater = new ArrayList<HttpRequestResponse>();

	public BurpController(IBurpExtenderCallbacks callbacks, boolean isBurp) {
		this.isBurp = isBurp;
		if (isBurp) {
			this.callbacks = callbacks;
			requestViewer = callbacks.createMessageEditor(BurpController.this, false);
			responseViewer = callbacks.createMessageEditor(BurpController.this, false);
		} else {
			requestResponse = new NullSink();
			responseViewer = new NullSink();
			requestResponse = new NullSink();
		}
	}

	public void init() {
		rootmessage = "Json error. Are you sure this is the root directory of a CouchDB instance at: " + url.toString()
				+ "?";
		connectmessage = "Unable to establish HTTP connection with: " + url.toString();
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

	public void configClient(String string) {
		try {
			this.url = new URL(string);
			init();
			if (!testConnection()) {
				String error = "Unable to create CouchClient";
				log.severe(error);
				throw new Exception(error);
			}
			cdbclient = new CouchDbClient("testinng", true, "http", "127.0.0.1", 5984, null, null);
			JOptionPane.showMessageDialog(null, "Connection to CouchDB established");
			listen();
		} catch (Exception e) {
			JOptionPane.showMessageDialog(null, e.getMessage());
		}

	}
	// Leaving this here because why not. Not using do to possible loop with
	// listening on both the jtree and databases for changes.
	// private void listenup() {
	// treeModel.addTreeModelListener(new TreeModelListener() {
	//
	// @Override
	// public void treeStructureChanged(TreeModelEvent e) {
	// // TODO Auto-generated method stub
	//
	// }
	//
	// @Override
	// public void treeNodesRemoved(TreeModelEvent e) {
	// // TODO Auto-generated method stub
	//
	// }
	//
	// @Override
	// public void treeNodesInserted(TreeModelEvent e) {
	// int index = e.getChildIndices()[0];
	// DefaultMutableTreeNode node = (DefaultMutableTreeNode)
	// root.getChildAt(index);
	// DefaultMutableTreeNode parent = (DefaultMutableTreeNode)
	// node.getParent();
	// Object userObject = node.getUserObject();
	// Object parentUserObject = parent.getUserObject();
	// if (userObject instanceof HttpRequestResponse) {
	// HttpRequestResponse requestResponse = (HttpRequestResponse) userObject;
	// if (parentUserObject instanceof HttpRequestResponse) {
	// HttpRequestResponse parentRequestResponse = (HttpRequestResponse)
	// parentUserObject;
	// requestResponse.setParentUuid(parentRequestResponse.getUUID());
	// requestResponse.setCategory(parentRequestResponse.getCategory());
	// } else if (parentUserObject instanceof OWASPCategory) {
	// OWASPCategory category = (OWASPCategory) parentUserObject;
	// requestResponse.setCategory(category);
	// }
	// client.put(requestResponse);
	// }
	// }
	//
	// @Override
	// public void treeNodesChanged(TreeModelEvent e) {
	// // TODO Auto-generated method stub
	//
	// }
	// });
	//
	// }

	private void listen() {
		Runnable runnable = new Runnable() {

			// TODO - WTF it do this for????
			@Override
			public void run() {
				Changes changes = cdbclient.changes().continuousChanges();
				while (changes.hasNext()) {
					Row row = changes.next();
					System.out.println(
							"Changes detected for document id: " + row.getId() + ", revision: " + row.getSeq());
					JsonObject json = getJsonObject(row.getId());
					if (json == null) {
						continue;
					}
					System.out.println(json);
					try {
						HttpRequestResponse fromJson = new HttpRequestResponse(json);
						DefaultMutableTreeNode search = searchByUUID(fromJson.getUUID());
						if (search == null) {
							addAutoOut(fromJson);
						} else {
							update(search, fromJson);
						}
					} catch (Exception e) {
						// System.out.println(
						// "Error unmarshalling raw JSON: " + json != null ?
						// json.toString() : "null json");
						// TODO FIX THIS
						e.printStackTrace();
						continue;
					}
				}
			}
		};
		exec.execute(runnable);
	}

	private void addAutoIn(HttpRequestResponse requestResponse) {
		
		//Check to see if we have any id's already in the model
		DefaultMutableTreeNode search = searchByUUID(requestResponse.getUUID());
		HttpRequestResponse searchHttp = (HttpRequestResponse) search.getUserObject();
		//Enter this if we find an id
		if (search != null) {
			//Checks if the incoming http has a parent if the current http has a parent
			if (requestResponse.getParentUuid() != null && searchHttp.getParentUuid() != null) {
				String parentUUID = requestResponse.getParentUuid();
				String searchUUID = searchHttp.getParentUuid();
				//Lets compare if the parent has changed
				if (!parentUUID.equals(searchUUID)) {
					//Search for the new parent value
					DefaultMutableTreeNode newparent = searchByUUID(parentUUID);
					//If we don't have the parent. We will have to come back to this one.
					if (newparent == null) {
						tryLater.add(requestResponse);
						//Otherwise, we'll add the new parent
					} else {
						search.setParent(newparent);
					}
				}
			}
		}
		if (search == null) {
			return;
		}
		// if (requestResponse)

		String currentRevision = ((HttpRequestResponse) search.getUserObject()).getRevision();
		// searchedHttp.getRevision();

	}

	private JsonObject getJsonObject(String id) {
		try {
			BufferedReader reader = new BufferedReader(new InputStreamReader(cdbclient.find(id)));
			String line;
			StringBuilder sb = new StringBuilder();
			while ((line = reader.readLine()) != null) {
				sb.append(line);
			}
			System.out.println(sb.toString());
			return new JsonParser().parse(new InputStreamReader(cdbclient.find(id))).getAsJsonObject();
		} catch (Exception e) {
			return null;
		}
	}

	private JSONObject getById(String id) throws UnirestException {
		return Unirest.get(url.toString()).asJson().getBody().getObject();
	}

	private void update(DefaultMutableTreeNode search, Object object) {
		if (object instanceof HttpRequestResponse) {
			HttpRequestResponse newHttp = (HttpRequestResponse) object;
			HttpRequestResponse oldhttp = (HttpRequestResponse) search.getUserObject();
			int newRev = Integer.parseInt(StringUtils.substringBefore(newHttp.getRevision(), "-"));
			int oldRev = Integer.parseInt(StringUtils.substringBefore(oldhttp.getRevision(), "-"));

			if (newRev > oldRev) {
				search.setUserObject(object);
			}
		}

	}

	public void addAutoOut(Object object) {
		// We store our list of changed nodes here to delete if something
		// happens to go wrong.
		List<DefaultMutableTreeNode> changes = new ArrayList<DefaultMutableTreeNode>();
		try {
			if (object == null) {
				log.warning("Can't add nothing to the tree???");
			}

			DefaultMutableTreeNode parentNode;
			if (object instanceof HttpRequestResponse) {
				log.fine("Object detected as: " + HttpRequestResponse.class.getName());
				HttpRequestResponse requestResponse = (HttpRequestResponse) object;
				if (requestResponse.getParentUuid() != null) {
					log.info(
							"Object has a parent uuid defined. Searching for uuid: " + requestResponse.getParentUuid());
					DefaultMutableTreeNode uuidParentNode = searchByUUID(requestResponse.getParentUuid());
					if (uuidParentNode == null) {
						log.severe("Parent uuid specified but the parent object does not exist.");
						return;
					}
					parentNode = uuidParentNode;
				} else {
					DefaultMutableTreeNode categoryParent = searchByCategory((HttpRequestResponse) object);
					if (categoryParent == null) {
						log.info("Category does not currently exist. Creating category: "
								+ requestResponse.getCategoryAsString());
						categoryParent = addChild(root, requestResponse.getCategory());
						log.fine("Category created");
						changes.add(categoryParent);
					}
					log.info("Category found as: " + ((OWASPCategory) categoryParent.getUserObject()).toString()
							+ ". Adding...");
					parentNode = categoryParent;
				}
				DefaultMutableTreeNode childNode = addChild(parentNode, requestResponse);
				changes.add(childNode);
				// Add Stuff to couch db
				Response response = cdbclient.post(requestResponse.toJson());
				if (response.getError() == null) {
					requestResponse.setUUID(response.getId());
					requestResponse.setRevision(response.getRev());
				} else {
					log.severe("Couch DB error: " + response.getError() + ". Reason: " + response.getReason());
					log.severe("Deleting element from tree");
					childNode.removeFromParent();
				}
				log.fine("Added child node to parent.");
			}
		} catch (Exception e) {
			log.severe("Exception caught. Rolling back changes.");
			for (DefaultMutableTreeNode node : changes) {
				log.severe("Removing: " + node.toString());
				node.removeFromParent();
				tree.updateUI();
			}
		}
	}

	/** Remove all nodes except the root node. */
	public void clear() {
		root.removeAllChildren();
		treeModel.reload();
	}

	public DefaultMutableTreeNode searchByUUID(String uuid) {
		if (uuid == null) {
			log.warning("Unable to search by a null uuid");
			return null;
		}
		Enumeration<DefaultMutableTreeNode> searchEnum = root.depthFirstEnumeration();
		log.fine("Searching tree by depth first for uuid: " + uuid);
		while (searchEnum.hasMoreElements()) {
			DefaultMutableTreeNode currentNode = searchEnum.nextElement();
			if (currentNode.getUserObject() instanceof HttpRequestResponse) {
				log.fine("Found a node that is an instance of HttpRequestResponse");
				HttpRequestResponse parentRequestResponse = (HttpRequestResponse) currentNode.getUserObject();
				String parentuuid = parentRequestResponse.getUUID();
				log.fine("Comparing uuid: " + uuid + " to uuid: " + parentuuid != null ? parentuuid : "null");
				if (parentuuid.equals(uuid)) {
					log.info("Match  found for uuid: " + uuid);
					return currentNode;
				}
			}
		}
		return null;
	}

	/** Remove the currently selected node. */
	public void removeCurrentNode() {
		TreePath currentSelection = tree.getSelectionPath();
		if (currentSelection != null) {
			DefaultMutableTreeNode currentNode = (DefaultMutableTreeNode) (currentSelection.getLastPathComponent());
			MutableTreeNode parent = (MutableTreeNode) (currentNode.getParent());
			if (parent != null) {
				treeModel.removeNodeFromParent(currentNode);
				return;
			}
		}

	}

	/** Add child to the currently selected node. */
	public DefaultMutableTreeNode addToSelected(Object child) {
		DefaultMutableTreeNode parentNode = null;
		TreePath parentPath = tree.getSelectionPath();

		if (parentPath == null) {
			parentNode = root;
		} else {
			parentNode = (DefaultMutableTreeNode) (parentPath.getLastPathComponent());
		}

		return addChild(parentNode, child);
	}

	public DefaultMutableTreeNode addChild(DefaultMutableTreeNode parent, Object child) {
		DefaultMutableTreeNode childNode = new DefaultMutableTreeNode(child);

		if (parent == null) {
			log.warning("No parent specified. Setting parent to root.");
			parent = root;
		}

		// It is key to invoke this on the TreeModel, and NOT
		// DefaultMutableTreeNode
		treeModel.insertNodeInto(childNode, parent, parent.getChildCount());

		// Make sure the user can see the lovely new node.
		tree.scrollPathToVisible(new TreePath(childNode.getPath()));
		return childNode;
	}

	private DefaultMutableTreeNode searchByCategory(HttpRequestResponse object) {
		log.fine("Searching for suitable parents for " + object.toString());
		Enumeration<DefaultMutableTreeNode> searchenum = root.breadthFirstEnumeration();
		while (searchenum.hasMoreElements()) {
			DefaultMutableTreeNode node = searchenum.nextElement();
			log.fine("Testing node with value: " + node.toString());
			Object userObject = node.getUserObject();
			if (userObject instanceof OWASPCategory) {
				if (object.getCategory().compareTo((OWASPCategory) userObject) == 0) {
					log.fine("OWASP category is: " + object.getCategoryAsString() + " with path: " + node.toString());
					return node;
				}
			}
		}
		return null;
	}

	public void setFrame(BurpFrame frame) {
		this.frame = frame;
	}

	public TreeModel getTreeModel() {
		return treeModel;
	}

	public void addDomain() {
		String hostname = JOptionPane.showInputDialog("Enter hostname:");
		String description = JOptionPane.showInputDialog("Description:");
		try {
			client.createDB(hostname);
		} catch (Exception e) {
			JOptionPane.showMessageDialog(null, e.getMessage());
		}
		// DBDescriptor descriptor = new DBDescriptor(hostname, description,
		// null);
		tree.updateUI();
	}

	public JTree getTree() {
		tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		return tree;
	}

	public void removeSelectedNode() {
		TreePath path = tree.getSelectionPath();
	}

	@Override
	public IHttpService getHttpService() {
		return requestResponse.getHttpService();
	}

	@Override
	public byte[] getRequest() {
		return requestResponse.getRequest();
	}

	@Override
	public byte[] getResponse() {
		return requestResponse.getResponse();
	}

	public IMessageEditor getRequestPreview() {
		return requestViewer;

	}

	public IMessageEditor getResponsePreview() {
		return responseViewer;
	}

	public TableModel getTableModel() {
		return tableModel;
	}

	public void addToStash(HttpRequestResponse http) {
		tableModel.addHttp(http);
	}

	public void stashToTree(int rowIndex) {
		if (rowIndex != -1) {
			addAutoOut(tableModel.getHttp(rowIndex));
		}
	}

	public void updatePreview(DefaultMutableTreeNode node) {
		Object userobject = node.getUserObject();
		if (userobject instanceof HttpRequestResponse) {
			requestResponse = (HttpRequestResponse) userobject;
		}
	}

}