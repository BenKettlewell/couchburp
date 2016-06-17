package com.prevsec.couchburp.ui;

import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.Label;

import javax.swing.JSplitPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;

import com.prevsec.couchburp.controller.BurpController;
import javax.swing.JButton;
import javax.swing.JDialog;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JLabel;
import java.awt.FlowLayout;
import javax.swing.JTextField;

public class BurpFrame extends JFrame {
	private BurpController controller;
	private JTextField txtCouchText;

	public BurpFrame(BurpController controller) {
		this.controller = controller;

		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		getContentPane().add(tabbedPane, BorderLayout.CENTER);

		JPanel optionspanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) optionspanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		tabbedPane.addTab("Options", null, optionspanel, null);

		JLabel lblNewLabel = new JLabel("CouchDB Url:");
		optionspanel.add(lblNewLabel);

		txtCouchText = new JTextField();
		optionspanel.add(txtCouchText);
		txtCouchText.setColumns(30);

		JButton btnSaveCouch = new JButton("Save");
		btnSaveCouch.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				controller.configClient(txtCouchText.getText());
			}
		});
		optionspanel.add(btnSaveCouch);

		JTree tree = controller.getTree();
		tree.setRootVisible(true);
		tree.setShowsRootHandles(true);

		JScrollPane stashscroll = new JScrollPane();
		stashscroll.setColumnHeaderView(new Label("The Stash"));
		JList<String> list = new JList<String>();
		stashscroll.setViewportView(list);
		JScrollPane treescroll = new JScrollPane();
		treescroll.setColumnHeaderView(new Label("The Tree"));
		treescroll.setViewportView(tree);

		JPanel horzRightPanel = new JPanel();
		horzRightPanel.setLayout(new BorderLayout(0, 0));
		horzRightPanel.add(treescroll);
		JSplitPane horzsplit = new JSplitPane();
		horzsplit.setOrientation(JSplitPane.HORIZONTAL_SPLIT);
		horzsplit.setLeftComponent(stashscroll);

		horzsplit.setRightComponent(horzRightPanel);

		JPanel panel = new JPanel();
		horzRightPanel.add(panel, BorderLayout.SOUTH);

		JButton btnHost = new JButton("Add Host");
		btnHost.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				controller.addDomain();
			}
		});
		panel.add(btnHost);

		JButton btnNewButton_1 = new JButton("New button");
		panel.add(btnNewButton_1);
		JSplitPane vertsplit = new JSplitPane();
		vertsplit.setOrientation(JSplitPane.VERTICAL_SPLIT);
		vertsplit.setLeftComponent(horzsplit);
		vertsplit.setRightComponent(new Label("preview will go here"));

		tabbedPane.addTab("The Stash and Tree", null, vertsplit, null);
	}

}
