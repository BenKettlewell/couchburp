package com.prevsec.couchburp.burp.jaxbjson;

import java.util.List;

public class DBDescriptor {

	private String uuid;
	private String revision;
	private String hostname;
	private String description;
	private List<String> notes;

	public DBDescriptor() {

	}

	public DBDescriptor(String hostname, String description, List<String> notes) {
		this.hostname = hostname;
		this.description = description;
		this.notes = notes;
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

	public List<String> getNotes() {
		return notes;
	}

	public void setNotes(List<String> notes) {
		this.notes = notes;
	}

}
