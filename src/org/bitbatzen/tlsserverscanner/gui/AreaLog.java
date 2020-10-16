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

import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.text.DefaultCaret;

import org.bitbatzen.tlsserverscanner.Util;
import org.bitbatzen.tlsserverscanner.scantask.*;


public class AreaLog extends Area {
	
	private JTextArea textArea;
	private JScrollPane scrollPane;
	
	private static final int LOG_TRIM_SIZE 			= 10000;
	private static final int LOG_TRIM_UPDATE_SIZE 	= 15000;
	private StringBuilder log;
	
	
	public AreaLog(MainWindow mainWindow) {
		super(mainWindow);
		
		panel.setLayout(null);
		textArea = new JTextArea();
		textArea.setEditable(false);
		textArea.setFont(MainWindow.FONT_LOG);
		textArea.setBackground(MainWindow.COLOR_BG_LOG);
		
		DefaultCaret caret = (DefaultCaret) textArea.getCaret();
		caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
		
		scrollPane = new JScrollPane(textArea);
		panel.add(scrollPane);
		
		log = new StringBuilder(LOG_TRIM_UPDATE_SIZE + 300);
	}
	
	public void addLogMessage(String message) {
		if (message != null && message.equals("") == false) {
			if (log.length() >= LOG_TRIM_UPDATE_SIZE) {
				int newStart = log.length() - LOG_TRIM_SIZE;
				int correctedStart = log.indexOf(Util.LF, newStart);
				log = log.replace(0, correctedStart, "...");
			}
			
			log.append(message + Util.LF);
			textArea.setText(log.toString());
		}
	}
	
	public void clearLog() {
		log.setLength(0);
		textArea.setText("");
	}
	
	@Override
	public void setPanelBounds(int x, int y, int width, int height) {
		super.setPanelBounds(x, y, width, height);
		
		textArea.setBounds(0, 0, width, height);
		scrollPane.setBounds(0, 0, width, height);		
	}

	@Override
	public synchronized void onScanTaskHandlerMessage(ScanTask scanTask, final String message) {
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				addLogMessage(message);
			}
		});
	}
}
