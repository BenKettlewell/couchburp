/* Component of CouchDB collaboration plugin for Burp Suite Professional Edition
 * Author: William Patrick Herrin 
 * Date: Jun 20, 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 */
package com.prevsec.couchburp.controller;

import java.net.URL;
import java.util.Enumeration;
import java.util.logging.Logger;
import java.util.stream.Stream;

import javax.swing.JOptionPane;
import javax.swing.JTree;
import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.MutableTreeNode;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import com.prevsec.couchburp.CouchClient;
import com.prevsec.couchburp.burp.jaxbjson.HttpRequestResponse;
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

	public void configClient(String string) {
		try {
			client = new CouchClient(new URL(string));
			JOptionPane.showMessageDialog(null, "Connection to CouchDB established");
			listenup();
		} catch (Exception e) {
			JOptionPane.showMessageDialog(null, e.getMessage());
		}
	}

	private void listenup() {
		treeModel.addTreeModelListener(new TreeModelListener() {

			@Override
			public void treeStructureChanged(TreeModelEvent e) {
				// TODO Auto-generated method stub

			}

			@Override
			public void treeNodesRemoved(TreeModelEvent e) {
				// TODO Auto-generated method stub

			}

			@Override
			public void treeNodesInserted(TreeModelEvent e) {

			}

			@Override
			public void treeNodesChanged(TreeModelEvent e) {
				// TODO Auto-generated method stub

			}
		});

	}

	public void addAuto(Object object) {
		if (object == null) {
			log.warning("Can't add nothing to the tree???");
		}

		DefaultMutableTreeNode parentNode;
		if (object instanceof HttpRequestResponse) {
			log.fine("Object detected as: " + HttpRequestResponse.class.getName());
			HttpRequestResponse requestResponse = (HttpRequestResponse) object;
			if (requestResponse.getParentUuid() != null) {
				log.info("Object has a parent uuid defined. Searching for uuid: " + requestResponse.getParentUuid());
				DefaultMutableTreeNode uuidParentNode = searchByUUID(requestResponse.getParentUuid());
				if (uuidParentNode == null) {
					log.severe("Parent uuid specified but the parent object does not exist.");
					requestResponse.setUUID(null);
				}
				parentNode = uuidParentNode;
			} else {
				DefaultMutableTreeNode categoryParent = searchByCategory((HttpRequestResponse) object);
				if (categoryParent == null) {
					log.info("Category does not currently exist. Creating category: "
							+ requestResponse.getCategoryAsString());
					DefaultMutableTreeNode categoryNode = addChild(root, requestResponse.getCategory());
					log.fine("Category created");
				}
				log.info("Category found as: " + ((OWASPCategory) categoryParent.getUserObject()).toString()
						+ ". Adding...");
				addChild(categoryParent, new HttpRequestResponse());
				log.fine("Added child node to parent.");

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
}