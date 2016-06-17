package com.prevsec.couchburp.ui;

import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import java.awt.Label;

import javax.swing.JSplitPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;

public class BurpFrame extends JFrame {
	public BurpFrame() {

		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		getContentPane().add(tabbedPane, BorderLayout.CENTER);

		JPanel optionspanel = new JPanel();
		tabbedPane.addTab("Options", null, optionspanel, null);

		JTree tree = new JTree();

		JScrollPane stashscroll = new JScrollPane();
		stashscroll.setColumnHeaderView(new Label("The Stash"));
		JList<String> list = new JList<String>();
		stashscroll.setViewportView(list);
		JScrollPane treescroll = new JScrollPane();
		treescroll.setColumnHeaderView(new Label("The Tree"));
		treescroll.setViewportView(tree);

		JSplitPane horzsplit = new JSplitPane();
		horzsplit.setOrientation(JSplitPane.HORIZONTAL_SPLIT);
		horzsplit.setLeftComponent(stashscroll);
		horzsplit.setRightComponent(treescroll);
		JSplitPane vertsplit = new JSplitPane();
		vertsplit.setOrientation(JSplitPane.VERTICAL_SPLIT);
		vertsplit.setLeftComponent(horzsplit);
		vertsplit.setRightComponent(new Label("preview will go here"));

		tabbedPane.addTab("The Stash and Tree", null, vertsplit, null);
	}

}
