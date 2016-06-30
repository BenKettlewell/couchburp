package com.prevsec.couchburp.ui;

import java.awt.BorderLayout;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTextPane;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;

import com.prevsec.couchburp.controller.BurpController;
import com.prevsec.couchburp.models.Note;

public class NotePane extends JPanel {

	private Note note;
	private BurpController controller;
	private boolean isburp;

	public NotePane(boolean b, Note userobject, BurpController burpController) throws BadLocationException {
		this.isburp = b;
		this.note = userobject;
		this.controller = burpController;
		setLayout(new BorderLayout(0, 0));

		JTextPane textPaneNote = new JTextPane();
		textPaneNote.setEditable(true);
		textPaneNote.getDocument().insertString(0, note.getNote(), null);
		add(textPaneNote);

		JButton btnUpdate = new JButton("Update");
		textPaneNote.getDocument().addDocumentListener(new DocumentListener() {

			@Override
			public void removeUpdate(DocumentEvent e) {
				try {
					note.setNote(e.getDocument().getText(0, e.getDocument().getLength()));
				} catch (BadLocationException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				try {
					note.setNote(e.getDocument().getText(0, e.getDocument().getLength()));
				} catch (BadLocationException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				try {
					note.setNote(e.getDocument().getText(0, e.getDocument().getLength()));
				} catch (BadLocationException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

			}
		});
		btnUpdate.addActionListener(e -> controller.updateNote(note));
		add(btnUpdate, BorderLayout.SOUTH);

	}

}
