package com.prevsec.couchburp.controller;

import java.net.URL;

import javax.persistence.EntityExistsException;
import javax.swing.JOptionPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.MutableTreeNode;
import javax.swing.tree.TreeModel;

import com.mashape.unirest.http.exceptions.UnirestException;
import com.prevsec.couchburp.CouchClient;
import com.prevsec.couchburp.burp.jaxbjson.DBDescriptor;
import com.prevsec.couchburp.ui.BurpFrame;

public class BurpController {
	private BurpFrame frame;
	private CouchClient client;
	// This is invisible, so the name is whatever
	private MutableTreeNode root = new DefaultMutableTreeNode("CouchDB");
	private TreeModel treeModel = new DefaultTreeModel(root);
	private JTree tree = new JTree(treeModel);

	public void configClient(String string) {
		try {
			client = new CouchClient(new URL(string));
			JOptionPane.showMessageDialog(null, "Connection to CouchDB established");
		} catch (Exception e) {
			JOptionPane.showMessageDialog(null, e.getMessage());
		}
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
	//	DBDescriptor descriptor = new DBDescriptor(hostname, description, null);
		tree.updateUI();
	}

	public JTree getTree() {
		return tree;
	}

}
