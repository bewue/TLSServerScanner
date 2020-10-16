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
import javax.swing.JTextField;

import org.bitbatzen.tlsserverscanner.Util;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.event.*;
 

public class DialogNewHost extends JDialog implements ActionListener {
	
	private MainWindow mainWindow;
	
	private JTextField textField;
	
	private JLabel infoLabel;
	
	private JButton buttonOk;
	private JButton buttonCancel;
	
	
	public DialogNewHost(MainWindow mainWindow) {
		super(mainWindow.getFrame(), "New Host", true);
		
		this.mainWindow = mainWindow;
		
	    JPanel topPanel = new JPanel(new BorderLayout());
	    topPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
	    
	    textField = new JTextField(26);
	    textField.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
	    textField.setFont(MainWindow.FONT_MEDIUM);
	    topPanel.add(textField, BorderLayout.NORTH);
	    
	    JLabel syntaxLabel = new JLabel("(syntax: host:port)");
	    syntaxLabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
	    syntaxLabel.setFont(MainWindow.FONT_SMALL);
	    syntaxLabel.setForeground(Color.GRAY);
	    topPanel.add(syntaxLabel, BorderLayout.SOUTH);
	    getContentPane().add(topPanel, BorderLayout.NORTH);

	    infoLabel = new JLabel(" ");
	    infoLabel.setFont(MainWindow.FONT_MEDIUM.deriveFont(Font.BOLD));
	    infoLabel.setForeground(Color.RED);
	    infoLabel.setHorizontalAlignment(JLabel.CENTER);
	    getContentPane().add(infoLabel, BorderLayout.CENTER);
	    
	    JPanel bottomPanel = new JPanel();
	    bottomPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 10, 5));
	    
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
        
	    setVisible(true);
	}
	
	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == buttonOk) {
			String host = Util.extractHost(textField.getText());
			int port = Util.extractPort(textField.getText());
			if (host == null || port == -1) {
				infoLabel.setText("Invalid Syntax!");
				return;
			}
			
			mainWindow.getAreaHosts().addHost(host, port);
		    setVisible(false); 
		    dispose();		
		}
		else if (e.getSource() == buttonCancel) {
		    setVisible(false); 
		    dispose();			
		}
	}
}
