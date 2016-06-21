/* Component of CouchDB collaboration plugin for Burp Suite Professional Edition
 * Author: William Patrick Herrin 
 * Date: Jun 20, 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 */
package com.prevsec.couchburp.burp.jaxbjson;

import java.util.List;

import javax.swing.tree.DefaultMutableTreeNode;

public class DBDescriptor extends DefaultMutableTreeNode {

	private String uuid = "root";
	private String revision;
	private String hostname;
	private String description;

	public DBDescriptor(String hostname, String description) {
		setUserObject(hostname);
		this.hostname = hostname;
		this.description = description;

	}

	public String getUuid() {
		return uuid;
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public String getRevision() {
		return revision;
	}

	public void setRevision(String revision) {
		this.revision = revision;
	}

	public String getHostname() {
		return hostname;
	}

	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}
}
