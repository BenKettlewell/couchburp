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
import javax.swing.ListSelectionModel;
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
		stash.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		stash.getSelectionModel().addListSelectionListener(e -> controller.updatePreview(stash.getSelectedRow()));
		stashscroll.setViewportView(stash);
		JScrollPane treescroll = new JScrollPane();
		treescroll.setColumnHeaderView(new Label("The Tree"));
		treescroll.setViewportView(tree);

		JPanel horzRightPanel = new JPanel();
		horzRightPanel.setLayout(new BorderLayout(0, 0));
		horzRightPanel.add(treescroll);
		JSplitPane horzsplit = new JSplitPane();
		horzsplit.setResizeWeight(0.5);
		horzsplit.setOrientation(JSplitPane.HORIZONTAL_SPLIT);
		JPanel horzLeftPanel = new JPanel();
		horzLeftPanel.setLayout(new BorderLayout(0, 0));
		horzLeftPanel.add(stashscroll, BorderLayout.CENTER);
		horzsplit.setLeftComponent(horzLeftPanel);

		JPanel leftPanelButtons = new JPanel();
		horzLeftPanel.add(leftPanelButtons, BorderLayout.SOUTH);

		JButton btnAddToStash = new JButton("Add By Category");
		btnAddToStash.addActionListener(e -> controller.addByCategory(stash.getSelectedRow()));
		leftPanelButtons.add(btnAddToStash);

		JButton btnAddToSelected = new JButton("Add To Selected");
		btnAddToSelected.addActionListener(
				e -> controller.addToSelected(stash.getSelectedRow(), tree.getLastSelectedPathComponent()));
		leftPanelButtons.add(btnAddToSelected);
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
		vertsplit.setResizeWeight(0.5);
		vertsplit.setOrientation(JSplitPane.VERTICAL_SPLIT);
		vertsplit.setLeftComponent(horzsplit);

		addTab("The Stash and Tree", null, vertsplit, null);

		JPanel infoPanel = new JPanel();
		controller.setInfo(infoPanel);
		vertsplit.setRightComponent(infoPanel);
		infoPanel.setLayout(new BorderLayout(0, 0));

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

			JButton multiTest = new JButton("Multi Post");
			multiTest.addActionListener(al -> controller.multiTest());
			dbgPanel.add(multiTest);
		}

	}

}
