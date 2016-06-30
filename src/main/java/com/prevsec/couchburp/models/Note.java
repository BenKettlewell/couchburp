package com.prevsec.couchburp.models;

import org.apache.commons.lang3.StringUtils;

import com.google.gson.JsonObject;

public class Note {

	private String type = "note";
	private String uuid;
	private String revision;
	private String parentUUID;
	private String note;

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

	public String getParentUUID() {
		return parentUUID;
	}

	public void setParentUUID(String parentUUID) {
		this.parentUUID = parentUUID;
	}

	public String getNote() {
		return note;
	}

	public void setNote(String note) {
		this.note = note;
	}

	public Note(String parentUUID, String note) {
		this.note = note;
		this.parentUUID = parentUUID;
	}

	public Note(String uuid, String revision, String parentUUID, String note) {
		this.uuid = uuid;
		this.revision = revision;
		this.parentUUID = parentUUID;
		this.note = note;
	}

	public Note(JsonObject json) {
		uuid = json.get("_id") != null ? json.get("_id").getAsString() : null;
		uuid = json.get("_rev") != null ? json.get("_rev").getAsString() : null;
		uuid = json.get("parent") != null ? json.get("parent").getAsString() : null;
		uuid = json.get("note") != null ? json.get("note").getAsString() : null;
	}

	public JsonObject toJson() {
		JsonObject json = new JsonObject();
		if (uuid != null) {
			json.addProperty("_id", uuid);
		}
		if (revision != null) {
			json.addProperty("_rev", revision);
		}
		json.addProperty("type", type);
		json.addProperty("parent", parentUUID);
		json.addProperty("note", note);
		return json;
	}

	@Override
	public String toString() {
		if (note != null) {
			if (note.length() > 25) {
				return StringUtils.abbreviate(note, 25);
			} else {
				return note;
			}
		} else {
			return "";
		}
	}

}
