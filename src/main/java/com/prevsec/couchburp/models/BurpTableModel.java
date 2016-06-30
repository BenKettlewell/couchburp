/*******************************************************************************
 * Author: William Patrick Herrin 
 * Date: 2016
 * Email: wherrin@prevsec.com, willherrin1@gmail.com
 *******************************************************************************/
package com.prevsec.couchburp.models;

import java.util.ArrayList;
import java.util.List;

import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;

import org.apache.commons.lang3.StringUtils;

import com.prevsec.couchburp.burp.jaxbjson.HttpRequestResponse;

public class BurpTableModel extends AbstractTableModel {

	private List<HttpRequestResponse> http = new ArrayList<HttpRequestResponse>();
	private String[] columns = { "Url", "Category" };

	@Override
	public int getRowCount() {
		return http.size();
	}

	@Override
	public int getColumnCount() {
		return columns.length;
	}

	// NULLS ARE REALLY REALLY BAD IN TABLES. THEY BREAK EVERYTHING AND MAKE
	// JAVA CRY. MAKE SURE STRINGS ARE DEFAULTED TO
	// BLANK NO MATTER WHAT
	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		switch (columnIndex) {
		case 0:
			return StringUtils
					.defaultString(StringUtils.substringBefore(new String(http.get(rowIndex).getRequest()), "\n"));
		case 1:
			return StringUtils.defaultString(http.get(rowIndex).getCategoryAsString());
		}
		return "";
	}

	@Override
	public String getColumnName(int column) {
		return columns[column];
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

	public void addHttp(HttpRequestResponse requestResponse) {
		http.add(requestResponse);
		fireTableDataChanged();
	}

	public void removeHttp(int rowIndex) {
		http.remove(rowIndex);
	}

	public HttpRequestResponse getHttp(int rowIndex) {
		return http.get(rowIndex);
	}
}
