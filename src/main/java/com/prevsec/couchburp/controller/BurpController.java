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
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import javax.persistence.EntityExistsException;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTree;
import javax.swing.table.TableModel;
import javax.swing.text.BadLocationException;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.MutableTreeNode;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.lightcouch.Changes;
import org.lightcouch.ChangesResult.Row;
import org.lightcouch.CouchDbClient;
import org.lightcouch.Response;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.mashape.unirest.http.HttpMethod;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import com.prevsec.couchburp.CouchClient;
import com.prevsec.couchburp.UUIDManager;
import com.prevsec.couchburp.models.BurpTableModel;
import com.prevsec.couchburp.models.HttpRequestResponse;
import com.prevsec.couchburp.models.Note;
import com.prevsec.couchburp.models.OWASPCategory;
import com.prevsec.couchburp.ui.BurpFrame;
import com.prevsec.couchburp.ui.HttpPane;
import com.prevsec.couchburp.ui.NotePane;
import com.prevsec.test.TestFactory;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IScanIssue;

public class BurpController implements IContextMenuFactory {
	private BurpFrame frame;
	private CouchClient client;
	// This is invisible, so the name is whatever
	private DefaultMutableTreeNode root = new DefaultMutableTreeNode("CouchDB");
	private DefaultTreeModel treeModel = new DefaultTreeModel(root);
	private JTree tree = new JTree(treeModel);
	private IBurpExtenderCallbacks callbacks;
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
	private JPanel infoPanel;

	public BurpController(IBurpExtenderCallbacks callbacks, boolean isBurp) {
		this.isBurp = isBurp;
		if (isBurp) {
			this.callbacks = callbacks;
		}
		callbacks.registerContextMenuFactory(BurpController.this);
		System.setOut(new PrintStream(callbacks.getStdout()));
		System.setErr(new PrintStream(callbacks.getStderr()));
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
					try {
						System.out.println("found changes");
						Row row = changes.next();
						List<HttpRequestResponse> httpRequestResponse = getAllHttps();
						List<Note> note = getAllNotes();
						rebuildTree(httpRequestResponse, note);
					} catch (Exception e) {
					}
				}
			}

		};
		exec.execute(runnable);
	}

	private List<Note> getAllNotes() {
		return getAllDocs().stream().filter(e -> e.get("type").getAsString().equals("note")).map(e -> new Note(e))
				.collect(Collectors.toList());
	}

	protected synchronized void rebuildTree(List<HttpRequestResponse> httpRequestResponse, List<Note> notes) {
		root.removeAllChildren();
		List<HttpRequestResponse> topLevel = httpRequestResponse.stream().filter(e -> e.getParentUuid() == null)
				.collect(Collectors.toList());
		log.info("Toplevel size is: " + topLevel.size());
		List<HttpRequestResponse> children = httpRequestResponse.stream().filter(e -> e.getParentUuid() != null)
				.collect(Collectors.toList());
		for (HttpRequestResponse http : topLevel) {
			try {
				addAuto(http);
			} catch (Exception e) {

			}
		}
		for (HttpRequestResponse http : children) {
			try {
				addAuto(http);
			} catch (Exception e) {

			}
		}
		for (Note note : notes) {
			try {
				addAuto(note);
			} catch (Exception e) {

			}
		}
		tree.updateUI();
		expandAll();
	}

	private void addAuto(Note note) {
		searchByUUID(note.getParentUUID()).add(new DefaultMutableTreeNode(note));
	}

	private void expandAll() {
		for (int i = 0; i < tree.getRowCount(); i++) {
			tree.expandRow(i);
		}
	}

	private List<HttpRequestResponse> getAllHttps() {
		return getAllDocs().stream().filter(e -> e.get("type").getAsString().equals("http"))
				.map(e -> new HttpRequestResponse(e)).collect(Collectors.toList());
		// List<HttpRequestResponse> httpList = new
		// ArrayList<HttpRequestResponse>();
		// for (JsonObject json : getAllDocs()) {
		// System.out.println(json.toString());
		// try {
		// HttpRequestResponse requestResponse = new HttpRequestResponse(json);
		// httpList.add(requestResponse);
		// } catch (Exception e) {
		// System.out.println(e.getMessage());
		// }
		// }
		// return httpList;
	}

	private List<JsonObject> getAllDocs() {
		return cdbclient.view("_all_docs").includeDocs(true).query(JsonObject.class);
	}

	private void addAutoIn(HttpRequestResponse requestResponse) {

		// Check to see if we have any id's already in the model
		DefaultMutableTreeNode search = searchByUUID(requestResponse.getUUID());
		HttpRequestResponse searchHttp = (HttpRequestResponse) search.getUserObject();
		// Enter this if we find an id
		if (search != null) {
			// Checks if the incoming http has a parent if the current http has
			// a parent
			if (requestResponse.getParentUuid() != null && searchHttp.getParentUuid() != null) {
				String parentUUID = requestResponse.getParentUuid();
				String searchUUID = searchHttp.getParentUuid();
				// Lets compare if the parent has changed
				if (!parentUUID.equals(searchUUID)) {
					// Search for the new parent value
					DefaultMutableTreeNode newparent = searchByUUID(parentUUID);
					// If we don't have the parent. We will have to come back to
					// this one.
					if (newparent == null) {
						tryLater.add(requestResponse);
						// Otherwise, we'll add the new parent
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

	public void addAuto(HttpRequestResponse httpRequestResponse) {
		if (httpRequestResponse.getParentUuid() == null) {
			DefaultMutableTreeNode categoryParent = searchByCategoryOrCreate(httpRequestResponse);
			categoryParent.add(new DefaultMutableTreeNode(httpRequestResponse));
		} else {
			searchByUUID(httpRequestResponse.getParentUuid()).add(new DefaultMutableTreeNode(httpRequestResponse));
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

	private DefaultMutableTreeNode searchByCategoryOrCreate(HttpRequestResponse object) {
		DefaultMutableTreeNode search;
		if ((search = searchByCategory(object)) == null) {
			root.add(search = new DefaultMutableTreeNode(object.getCategory()));
		}
		return search;
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

	public TableModel getTableModel() {
		return tableModel;
	}

	public void addToStash(HttpRequestResponse http) {
		tableModel.addHttp(http);
	}

	public void stashToTree(int rowIndex) {
		if (rowIndex != -1) {
			cdbclient.post(tableModel.getHttp(rowIndex).toJson());
		}
	}

	public void updatePreview(DefaultMutableTreeNode node) {
		Object userobject = node.getUserObject();
		if (userobject instanceof HttpRequestResponse) {
			infoPanel.removeAll();
			infoPanel.add(new HttpPane(true, (HttpRequestResponse) userobject, this, callbacks));
		} else if (userobject instanceof Note) {
			infoPanel.removeAll();
			try {
				infoPanel.add(new NotePane(true, (Note) userobject, this));
			} catch (BadLocationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	public void multiTest() {
		HttpRequestResponse requestResponse = TestFactory.createHttpRequestResponse("123");
		cdbclient.post(requestResponse.toJson());
		cdbclient.post(requestResponse.toJson());
		requestResponse = TestFactory.createHttpRequestResponse("1234", "1-12345");
		cdbclient.post(requestResponse.toJson());
		cdbclient.post(requestResponse.toJson());

	}

	public void setInfo(JPanel infoPanel) {
		this.infoPanel = infoPanel;
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		List<JMenuItem> menu = new ArrayList<JMenuItem>();
		JMenuItem send = new JMenuItem("Send to Stash");
		send.addActionListener(e -> menuAction(invocation));
		menu.add(send);
		return menu;
	}

	public void menuAction(IContextMenuInvocation invocation) {
		if (invocation.getInvocationContext() == invocation.CONTEXT_SCANNER_RESULTS) {
			IScanIssue[] scanIssues = invocation.getSelectedIssues();
			for (IScanIssue issue : scanIssues) {
				for (IHttpRequestResponse http : issue.getHttpMessages()) {
					HttpRequestResponse requestResponse = new HttpRequestResponse(null, null,
							new String(http.getRequest()), new String(http.getResponse()), http.getComment(), null,
							http.getHighlight(), http.getHttpService());
					tableModel.addHttp(requestResponse);
					tableModel.fireTableDataChanged();
				}
			}
		} else {
			IHttpRequestResponse[] messages = invocation.getSelectedMessages();
			for (IHttpRequestResponse http : messages) {
				HttpRequestResponse requestResponse = new HttpRequestResponse(null, null, new String(http.getRequest()),
						new String(http.getResponse()), http.getComment(), null, http.getHighlight(),
						http.getHttpService());
				tableModel.addHttp(requestResponse);
				tableModel.fireTableDataChanged();
			}
		}
	}

	public void updatePreview(int selectedRow) {
		HttpRequestResponse http = tableModel.getHttp(selectedRow);
		infoPanel.removeAll();
		infoPanel.add(new HttpPane(true, http, this, callbacks));
	}

	public void updateNote(Note note) {
		if (note.getUuid() == null) {
			cdbclient.post(note.toJson());
		} else {
			cdbclient.update(note.toJson());
		}
		infoPanel.removeAll();
	}

	public void updateHttp(HttpRequestResponse http) {
		if (http.getUUID() == null) {
			cdbclient.post(http.toJson());
		} else {
			cdbclient.update(http.toJson());
		}
		infoPanel.removeAll();
	}

	public void addByCategory(int selectedRow) {
		HttpRequestResponse http = tableModel.getHttp(selectedRow);
		if (http.getUUID() == null) {
			cdbclient.post(http.toJson());
		} else {
			cdbclient.update(http.toJson());
		}
	}

	public void addToSelected(int selectedRow, Object lastSelectedPathComponent) {
		HttpRequestResponse parent = (HttpRequestResponse) lastSelectedPathComponent;
		HttpRequestResponse http = tableModel.getHttp(selectedRow);
		http.setParentUuid(parent.getUUID());
		if (http.getUUID() == null) {
			cdbclient.post(http.toJson());
		} else {
			cdbclient.update(http.toJson());
		}

	}

}