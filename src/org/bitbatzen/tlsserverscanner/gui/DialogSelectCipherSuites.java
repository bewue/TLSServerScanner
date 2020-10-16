/*
 *  Copyright (C) 2015 Benjamin W. (bitbatzen@gmail.com)
 *
 *  This file is part of TLSServerScanner.
 *
 *  TLSServerScanner is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  TLSServerScanner is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with TLSServerScanner.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.bitbatzen.tlsserverscanner.gui;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.bitbatzen.tlsserverscanner.Util;
import org.bitbatzen.tlsserverscanner.scantask.SSLUtil;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Point;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
 

public class DialogSelectCipherSuites extends JDialog implements ActionListener, WindowListener {
	
	public enum DialogType {
		CIPHER_SUITES_TO_TEST,
		CIPHER_SUITES_FOR_COLLECTING_CERT
	}
	
	private MainWindow mainWindow;
	
	private JButton buttonOk;
	
	private JLabel labelCiphersInfo;
	
	private JCheckBox cbToggleAll;
	private JCheckBox cbSelectFiltered;
	
	private JTextField tfFilter;
	private JLabel labelFilterInfo;
	
	private List<JCheckBox> cipherSuites; 
	
	private boolean selectionChanged;
	
	private DialogType dialogType;
	
	private static DialogSelectCipherSuitesData[] data = null;
	
	
	public DialogSelectCipherSuites(MainWindow mainWindow, DialogType dialogType, String title) {
		super(mainWindow.getFrame(), title, true);
		
		String header = "";
		if (dialogType == DialogType.CIPHER_SUITES_TO_TEST) {
			header = "Select cipher suites to test!";
		}
		else if (dialogType == DialogType.CIPHER_SUITES_FOR_COLLECTING_CERT) {
			header = "Select supported cipher suites for"
					+ Util.BR + "fetching the certificates!";
		}
		
		this.mainWindow = mainWindow;
		this.dialogType = dialogType;
		selectionChanged = false;
		
		setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
		addWindowListener(this);
		setSize(550, 630);
		
	    JPanel panel = new JPanel();
	    BoxLayout layout = new BoxLayout(panel, BoxLayout.Y_AXIS);
	    panel.setLayout(layout);
	    panel.setBorder(BorderFactory.createEmptyBorder(15, 25, 25, 25));
	    
	    // header label
	    JLabel labelHeader = new JLabel("<html>" + header + "</html>");
	    labelHeader.setFont(MainWindow.FONT_HUGE);
	    labelHeader.setForeground(MainWindow.COLOR_DIALOG_HEADER);
	    labelHeader.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
	    panel.add(labelHeader);
	    
        // info label
	    labelCiphersInfo = new JLabel("<html>Available cipher suites are depending on the installed"
	    		+ "<br> version of the java runtime environment! (current: " + Util.getJavaVersionString() + ")</html>");
	    labelCiphersInfo.setFont(MainWindow.FONT_SMALL);
	    labelCiphersInfo.setForeground(MainWindow.COLOR_HINT);
	    labelCiphersInfo.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
	    panel.add(labelCiphersInfo);
	    
	    // checkbox toggle all
	    cbToggleAll = new JCheckBox("Toggle All");
	    cbToggleAll.setSelected(getData().toggleAllSelected);
	    cbToggleAll.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				selectionChanged = true;
				for (JCheckBox cb : cipherSuites) {
					cb.setSelected(cbToggleAll.isSelected());
				}
			}
		});
	    panel.add(cbToggleAll);
	    
	    panel.add(Box.createRigidArea(new Dimension(0, 5)));
	    
	    // checkbox select filtered
	    cbSelectFiltered = new JCheckBox("Select Filtered");
	    cbSelectFiltered.setSelected(getData().selectFilteredSelected);
	    cbSelectFiltered.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent arg0) {
				selectionChanged = true;
				onFilterChanged(cbSelectFiltered.isSelected());				
			}
		});
	    panel.add(cbSelectFiltered);
	    
	    panel.add(Box.createRigidArea(new Dimension(0, 5)));
	    
	    // filter
	    tfFilter = new JTextField(getData().filterSting);
	    tfFilter.setFont(MainWindow.FONT_MEDIUM);
	    tfFilter.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
	    tfFilter.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void removeUpdate(DocumentEvent e) {
				onFilterChanged(cbSelectFiltered.isSelected());
			}
			@Override
			public void insertUpdate(DocumentEvent e) {
				onFilterChanged(cbSelectFiltered.isSelected());
			}
			@Override
			public void changedUpdate(DocumentEvent e) {
				onFilterChanged(cbSelectFiltered.isSelected());
			}
		});
	    panel.add(tfFilter);
	    
	    labelFilterInfo = new JLabel("(filter syntax: whitespace seperated values (aes ecdhe))");
	    labelFilterInfo.setFont(MainWindow.FONT_SMALL);
	    labelFilterInfo.setForeground(Color.GRAY);
	    labelFilterInfo.setBorder(BorderFactory.createEmptyBorder(5, 0, 20, 0));
	    panel.add(labelFilterInfo);
	    
	    // available cipher suites
	    JScrollPane scrollPane = new JScrollPane(panel);
	    getContentPane().add(scrollPane, BorderLayout.CENTER);
	    scrollPane.setPreferredSize(new Dimension(450, 600));
	    
	    List<String> availableCipherSuites = SSLUtil.getAvailableCipherSuites();
 	    Collections.sort(availableCipherSuites);
	    
	    cipherSuites = new ArrayList<JCheckBox>();
	    for (String s : availableCipherSuites) {
	    	JCheckBox cb = new JCheckBox(s, getData().selectedCipherSuites.contains(s));
	    	cb.addActionListener(this);
	    	cipherSuites.add(cb);
	    	panel.add(cb);
	    }
	    
	    panel.add(Box.createRigidArea(new Dimension(0, 20)));
	    
        // button ok
	    buttonOk = new JButton("Ok");
	    buttonOk.addActionListener(this);
	    panel.add(buttonOk);
	    
	    onFilterChanged(false);
	    
        Dimension parentSize = mainWindow.getFrame().getSize(); 
        Point p = mainWindow.getFrame().getLocation(); 
        setLocation(p.x + parentSize.width / 2 - getWidth() / 2, p.y + 50);
	    setVisible(true);
	}
	
	private static DialogSelectCipherSuitesData getData(DialogType dialogType) {
		if (data == null) {
			data = new DialogSelectCipherSuitesData[2];
			data[0] = new DialogSelectCipherSuitesData();
			data[1] = new DialogSelectCipherSuitesData();
			data[1].selectedCipherSuites = SSLUtil.getAvailableCipherSuites();
		}
		
		if (dialogType == DialogType.CIPHER_SUITES_TO_TEST) {
			return data[0];
		}
		else {
			return data[1];
		}		
	}
	
	private DialogSelectCipherSuitesData getData() {
		return getData(dialogType);
	}
	
	public static List<String> getSelectedCipherSuites(DialogType dialogType) {
		return getData(dialogType).selectedCipherSuites;
	}
	
	private void setElementsEnabled(boolean enabled) {
		cbSelectFiltered.setEnabled(enabled);
		cbToggleAll.setEnabled(enabled);
		tfFilter.setEnabled(enabled);
		labelFilterInfo.setEnabled(enabled);
		labelCiphersInfo.setEnabled(enabled);
		for (JCheckBox cb : cipherSuites) {
			cb.setEnabled(enabled);
		}
	}
	
	private void onFilterChanged(boolean selectFiltered) {
		if (selectFiltered) {
			selectionChanged = true;
		}
		
		String[] filter = tfFilter.getText().split(" ");
		for (JCheckBox cb : cipherSuites) {
			boolean filtered = true;
			for (String s : filter) {
				if (cb.getText().contains(s.toUpperCase()) == false) {
					filtered = false;
					break;
				}
			}
			
			if (filtered) {
				cb.setForeground(Color.BLACK);												
			}
			else {
				cb.setForeground(Color.LIGHT_GRAY);
			}
			
			if (selectFiltered) {
				cb.setSelected(filtered);
			}
		}
	}
	
	private boolean checkSelectedCipherSuitesCount() {
		if (dialogType == DialogType.CIPHER_SUITES_FOR_COLLECTING_CERT) {
			int count = 0;
			for (JCheckBox cb : cipherSuites) {
				if (cb.isSelected()) {
					count++;
				}
			}
			if (count == 0) {
				mainWindow.showMessageDialog("Cipher Suites", "At least one cipher suite has to be selected!");
				return false;
			}
			else {
				return true;
			}
		}
		else {
			return true;
		}
	}
	
	private void save() {
		DialogSelectCipherSuitesData data = getData();
		
		data.selectFilteredSelected = cbSelectFiltered.isSelected();
		data.toggleAllSelected = cbToggleAll.isSelected();
		data.filterSting = tfFilter.getText();

		data.selectedCipherSuites.clear();
		for (JCheckBox cb : cipherSuites) {
			if (cb.isSelected()) {
				data.selectedCipherSuites.add(cb.getText());
			}
		}
	}
	
	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == buttonOk) {
			if (checkSelectedCipherSuitesCount()) {
				save();
			    setVisible(false); 
			    dispose();	
			}
		}
		else if (e.getSource() instanceof JCheckBox) {
			selectionChanged = true;
		}
	}

	@Override
	public void windowActivated(WindowEvent arg0) {
	}

	@Override
	public void windowClosed(WindowEvent arg0) {
	}

	@Override
	public void windowClosing(WindowEvent arg0) {
		if (selectionChanged) {
			if (mainWindow.showConfirmDialog("Close", "Save changes?")) {
				if (checkSelectedCipherSuitesCount()) {
					save();
				}
				else {
					return;
				}
			}
		}
		
	    setVisible(false); 
	    dispose();
	}

	@Override
	public void windowDeactivated(WindowEvent arg0) {
	}

	@Override
	public void windowDeiconified(WindowEvent arg0) {
	}

	@Override
	public void windowIconified(WindowEvent arg0) {
	}

	@Override
	public void windowOpened(WindowEvent arg0) {
	}
}
