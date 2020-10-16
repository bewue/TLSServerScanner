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

import org.bitbatzen.tlsserverscanner.Util;
import org.bitbatzen.tlsserverscanner.scantask.SSLUtil;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Point;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;
 

public class DialogSelectProtocols extends JDialog implements ActionListener, WindowListener {
	
	private MainWindow mainWindow;
	
	private JButton buttonOk;
	
	private JLabel labelProtocolsInfo;
	
	private List<JCheckBox> protocols; 
	
	private boolean selectionChanged;

	private static List<String> selectedProtocols = new ArrayList<>();
	
	
	public DialogSelectProtocols(MainWindow mainWindow) {
		super(mainWindow.getFrame(), "Protocols", true);
		
		this.mainWindow = mainWindow;
		selectionChanged = false;

		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		addWindowListener(this);
		setSize(500, 350);
		
	    JPanel panel = new JPanel();
	    BoxLayout layout = new BoxLayout(panel, BoxLayout.Y_AXIS);
	    panel.setLayout(layout);
	    panel.setBorder(BorderFactory.createEmptyBorder(15, 25, 25, 25));
	    
	    // header label
	    JLabel labelHeader = new JLabel("<html>Select protocols to test!</html>");
	    labelHeader.setFont(MainWindow.FONT_HUGE);
	    labelHeader.setForeground(MainWindow.COLOR_DIALOG_HEADER);
	    labelHeader.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
	    panel.add(labelHeader);
	    
        // info label
	    labelProtocolsInfo = new JLabel("<html>Available protocols are depending on the installed"
	    		+ "<br> version of the java runtime environment! (current: " + Util.getJavaVersionString() + ")</html>");
	    labelProtocolsInfo.setFont(MainWindow.FONT_SMALL);
	    labelProtocolsInfo.setForeground(MainWindow.COLOR_HINT);
	    labelProtocolsInfo.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
	    panel.add(labelProtocolsInfo);
	    
	    // available protocols
	    JScrollPane scrollPane = new JScrollPane(panel);
	    getContentPane().add(scrollPane, BorderLayout.CENTER);
	    scrollPane.setPreferredSize(new Dimension(450, 600));
	    
	    List<String> availableProtocols = SSLUtil.getAvailableProtocols();
// 	    Collections.sort(availableProtocols);
	    
	    protocols = new ArrayList<JCheckBox>();
	    for (String s : availableProtocols) {
	    	JCheckBox cb = new JCheckBox(s, selectedProtocols.contains(s));
	    	cb.addActionListener(this);
	    	protocols.add(cb);
	    	panel.add(cb);
	    }
	    
	    panel.add(Box.createRigidArea(new Dimension(0, 20)));
	    
        // button ok
	    buttonOk = new JButton("Ok");
	    buttonOk.addActionListener(this);
	    panel.add(buttonOk);
	    
        Dimension parentSize = mainWindow.getFrame().getSize(); 
        Point p = mainWindow.getFrame().getLocation(); 
        setLocation(p.x + parentSize.width / 2 - getWidth() / 2, p.y + 50);
	    setVisible(true);
	}
	
	public static final List<String> getSelectedProtocols() {
		return selectedProtocols;
	}
	
	private void save() {
		selectedProtocols.clear();
		for (JCheckBox cb : protocols) {
			if (cb.isSelected()) {
				selectedProtocols.add(cb.getText());
			}
		}
	}
	
	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == buttonOk) {
			save();
		    setVisible(false); 
		    dispose();	
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
				save();
			}			
		}
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
