package com.prevsec.couchburp.controller;

import java.util.List;

import javax.swing.JMenuItem;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;

public class ContextMenuFactory implements IContextMenuFactory {

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		return null;
	}

}
