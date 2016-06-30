package com.prevsec.couchburp.ui;

import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

import com.prevsec.couchburp.controller.BurpController;
import com.prevsec.couchburp.models.HttpRequestResponse;
import com.prevsec.couchburp.models.OWASPCategory;

import burp.IBurpExtenderCallbacks;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.DefaultComboBoxModel;

public class HttpPane extends JPanel implements IMessageEditorController {

	private HttpRequestResponse http;
	private IMessageEditor response;
	private IMessageEditor request;
	private BurpController controller;
	private JComboBox<OWASPCategory> combo = new JComboBox<OWASPCategory>();
	private JTabbedPane tabbed = new JTabbedPane();

	public HttpPane(boolean isburp, HttpRequestResponse requestResponse, BurpController burpController,
			IBurpExtenderCallbacks callbacks) {
		if (isburp) {
			this.request = callbacks.createMessageEditor(HttpPane.this, false);
			this.response = callbacks.createMessageEditor(HttpPane.this, false);
			this.http = requestResponse;
			request.setMessage(http.getRequest(), true);
			response.setMessage(http.getResponse(), false);
			tabbed.add("Request", request.getComponent());
			tabbed.add("Response", response.getComponent());
		}
		this.controller = controller;
		setLayout(new BorderLayout(0, 0));
		add(tabbed, BorderLayout.CENTER);
		JPanel panel = new JPanel();
		add(panel, BorderLayout.SOUTH);
		panel.setLayout(new BorderLayout(0, 0));
		combo.setModel(new DefaultComboBoxModel(OWASPCategory.values()));
		combo.setSelectedItem(http.getCategory());
		panel.add(combo);

		JButton btnUpdate = new JButton("Update");
		btnUpdate.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				http.setCategory((OWASPCategory) combo.getSelectedItem());
				controller.updateHttp(http);
			}
		});
		panel.add(btnUpdate, BorderLayout.EAST);
	}

	@Override
	public IHttpService getHttpService() {
		return http.getHttpService();
	}

	@Override
	public byte[] getRequest() {
		return http.getRequest();
	}

	@Override
	public byte[] getResponse() {
		return http.getResponse();
	}

}
