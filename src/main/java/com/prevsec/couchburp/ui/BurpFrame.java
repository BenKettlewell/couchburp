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
package com.prevsec.couchburp.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Label;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.DefaultMutableTreeNode;

import com.prevsec.couchburp.controller.BurpController;
import com.prevsec.couchburp.models.OWASPCategory;
import com.prevsec.test.TestFactory;

public class BurpFrame extends JTabbedPane {
	private boolean isBurp;
	private BurpController controller;
	private JTextField txtCouchText;

	public BurpFrame(BurpController controller, boolean isBurp) {
		this.isBurp = isBurp;
		this.controller = controller;

		JTree tree = controller.getTree();
		tree.setRootVisible(true);
		tree.setShowsRootHandles(true);
		tree.addTreeSelectionListener(new TreeSelectionListener() {
			@Override
			public void valueChanged(TreeSelectionEvent e) {
				controller.updatePreview((DefaultMutableTreeNode) tree.getLastSelectedPathComponent());
			}
		});
		JScrollPane stashscroll = new JScrollPane();
		stashscroll.setColumnHeaderView(new Label("The Stash"));

		JTable stash = new JTable(controller.getTableModel());

		stashscroll.setViewportView(stash);
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

		addTab("The Stash and Tree", null, vertsplit, null);

		JPanel infoPanel = new JPanel();
		vertsplit.setRightComponent(infoPanel);
		infoPanel.setLayout(new BorderLayout(0, 0));

		JTabbedPane requestResponsePane = new JTabbedPane(JTabbedPane.TOP);
		if (isBurp) {
			requestResponsePane.addTab("Request", controller.getRequestPreview().getComponent());
			requestResponsePane.addTab("Response", controller.getResponsePreview().getComponent());
		} else {
			requestResponsePane.add("Request", new Label("Burp Editor would go here"));
			requestResponsePane.add("Request", new Label("Burp Editor would go here"));
		}
		infoPanel.add(requestResponsePane, BorderLayout.NORTH);

		JPanel infoPane = new JPanel();
		infoPanel.add(infoPane, BorderLayout.CENTER);
		GridBagLayout gbl_infoPane = new GridBagLayout();
		gbl_infoPane.columnWidths = new int[] { 127, 787, 0 };
		gbl_infoPane.rowHeights = new int[] { 40, 0, 0, 0 };
		gbl_infoPane.columnWeights = new double[] { 0.0, 1.0, Double.MIN_VALUE };
		gbl_infoPane.rowWeights = new double[] { 0.0, 1.0, 0.0, Double.MIN_VALUE };
		infoPane.setLayout(gbl_infoPane);

		JLabel lblCategory = new JLabel("Category:");
		GridBagConstraints gbc_lblCategory = new GridBagConstraints();
		gbc_lblCategory.fill = GridBagConstraints.HORIZONTAL;
		gbc_lblCategory.insets = new Insets(0, 0, 5, 5);
		gbc_lblCategory.gridx = 0;
		gbc_lblCategory.gridy = 0;
		infoPane.add(lblCategory, gbc_lblCategory);

		JComboBox comboBox = new JComboBox();
		comboBox.setModel(new DefaultComboBoxModel(OWASPCategory.values()));
		GridBagConstraints gbc_comboBox = new GridBagConstraints();
		gbc_comboBox.fill = GridBagConstraints.BOTH;
		gbc_comboBox.insets = new Insets(0, 0, 5, 0);
		gbc_comboBox.gridx = 1;
		gbc_comboBox.gridy = 0;
		infoPane.add(comboBox, gbc_comboBox);

		JLabel lblNewLabel_1 = new JLabel("Comment:");
		GridBagConstraints gbc_lblNewLabel_1 = new GridBagConstraints();
		gbc_lblNewLabel_1.fill = GridBagConstraints.HORIZONTAL;
		gbc_lblNewLabel_1.insets = new Insets(0, 0, 5, 5);
		gbc_lblNewLabel_1.gridx = 0;
		gbc_lblNewLabel_1.gridy = 1;
		infoPane.add(lblNewLabel_1, gbc_lblNewLabel_1);

		JTextArea textArea = new JTextArea();
		GridBagConstraints gbc_textArea = new GridBagConstraints();
		gbc_textArea.insets = new Insets(0, 0, 5, 0);
		gbc_textArea.fill = GridBagConstraints.BOTH;
		gbc_textArea.gridx = 1;
		gbc_textArea.gridy = 1;
		infoPane.add(textArea, gbc_textArea);

		JButton btnUpdate = new JButton("Update");
		GridBagConstraints gbc_btnUpdate = new GridBagConstraints();
		gbc_btnUpdate.fill = GridBagConstraints.BOTH;
		gbc_btnUpdate.insets = new Insets(0, 0, 0, 5);
		gbc_btnUpdate.gridx = 0;
		gbc_btnUpdate.gridy = 2;
		infoPane.add(btnUpdate, gbc_btnUpdate);

		JPanel optionspanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) optionspanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		addTab("Options", null, optionspanel, null);

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
		if (!isBurp) {
			JPanel dbgPanel = new JPanel();
			infoPanel.add(dbgPanel, BorderLayout.SOUTH);

			JLabel lblDebugFunctions = new JLabel("Debug Functions:");
			dbgPanel.add(lblDebugFunctions);

			JButton btnCreateHttp = new JButton("CreateHttp");
			btnCreateHttp.addActionListener(al -> controller.addToStash(TestFactory.createHttpRequestResponse()));
			dbgPanel.add(btnCreateHttp);

			JButton btnStashToTree = new JButton("StashToTree");
			btnStashToTree.addActionListener(al -> controller.stashToTree(stash.getSelectedRow()));
			dbgPanel.add(btnStashToTree);

			JButton btnDebugConfig = new JButton("Debug Config");
			btnDebugConfig.addActionListener(al -> controller.configClient("http://localhost:5984/"));
			dbgPanel.add(btnDebugConfig);
		}

	}

}
