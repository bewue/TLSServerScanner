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
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JTextArea;

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.event.*;


public class DialogMessage extends JDialog implements ActionListener {
	
	private MainWindow mainWindow;
	
	private JTextArea infoArea;
	
	private JButton buttonOk;
	
	
	public DialogMessage(MainWindow mainWindow, String title, String text) {
		super(mainWindow.getFrame(), title, true);
		
		this.mainWindow = mainWindow;
		
		setResizable(false);
		
	    infoArea = new JTextArea(text);
	    infoArea.setEditable(false);
	    infoArea.setFont(MainWindow.FONT_MEDIUM.deriveFont(Font.BOLD));
	    infoArea.setBorder(BorderFactory.createEmptyBorder(20, 30, 15, 30));
	    getContentPane().add(infoArea, BorderLayout.CENTER);
	    
	    JPanel bottomPanel = new JPanel();
	    bottomPanel.setBorder(BorderFactory.createEmptyBorder(5, 20, 10, 20));
	    
	    buttonOk = new JButton("Ok");
	    buttonOk.addActionListener(this);
	    bottomPanel.add(buttonOk);
	    
	    getContentPane().add(bottomPanel, BorderLayout.SOUTH);
	    setDefaultCloseOperation(DISPOSE_ON_CLOSE);
	    pack();
	    
	    mainWindow.setDefaultPopupPosition(this);
	}
	
	public void showDialog() {
		setVisible(true);
	}
	
	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == buttonOk) {
		    setVisible(false); 
		    dispose();
		}
	}
}
