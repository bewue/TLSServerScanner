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
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JDialog;
import javax.swing.JPanel;

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.event.*;
 

public class DialogConfirm extends JDialog implements ActionListener {
	
	private MainWindow mainWindow;
	
	private JLabel infoLabel;
	
	private JButton buttonOk;
	private JButton buttonCancel;
	
	private boolean returnValue = false;
	
	
	public DialogConfirm(MainWindow mainWindow, String title, String text) {
		super(mainWindow.getFrame(), title, true);
		
		this.mainWindow = mainWindow;
		
		setResizable(false);
		
	    infoLabel = new JLabel(text);
	    infoLabel.setFont(MainWindow.FONT_MEDIUM.deriveFont(Font.BOLD));
	    infoLabel.setBorder(BorderFactory.createEmptyBorder(20, 30, 15, 30));
	    infoLabel.setHorizontalAlignment(JLabel.CENTER);
	    getContentPane().add(infoLabel, BorderLayout.CENTER);
	    
	    JPanel bottomPanel = new JPanel();
	    bottomPanel.setBorder(BorderFactory.createEmptyBorder(5, 20, 10, 20));
	    
	    buttonOk = new JButton("Ok");
	    buttonOk.addActionListener(this);
	    bottomPanel.add(buttonOk);
	    
	    buttonCancel = new JButton("Cancel");
	    buttonCancel.addActionListener(this);
	    bottomPanel.add(buttonCancel); 
	    
	    getContentPane().add(bottomPanel, BorderLayout.SOUTH);
	    setDefaultCloseOperation(DISPOSE_ON_CLOSE);
	    pack();
	    
	    mainWindow.setDefaultPopupPosition(this);
	}
	
	public boolean showDialog() {
		setVisible(true);
		return returnValue;
	}
	
	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == buttonOk) {
			returnValue = true;
		    setVisible(false); 
		    dispose();		
		}
		else if (e.getSource() == buttonCancel) {
			returnValue = false;
		    setVisible(false); 
		    dispose();			
		}
	}
}
