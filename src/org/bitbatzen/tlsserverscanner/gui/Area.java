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

import javax.swing.JPanel;

import org.bitbatzen.tlsserverscanner.scantask.*;


public class Area implements IScanTaskHandlerListener {

	public final static int BORDER_WIDTH = 2;
	
	protected ScanTaskHandler scanTaskHandler;
	
	protected JPanel panel;
	
	protected MainWindow mainWindow;
	
	
	public Area(MainWindow mainWindow) {
		this.mainWindow = mainWindow;
		
		panel = new JPanel();
		
		scanTaskHandler = null;
	}
	
	public JPanel getPanel() {
		return panel;
	}
	
	public void setPanelBounds(int x, int y, int width, int height) {
		panel.setBounds(x, y, width, height);
	}
	
	public void setScanTaskHandler(ScanTaskHandler scanTaskHandler) {
		this.scanTaskHandler = scanTaskHandler;
		scanTaskHandler.addListener(this);
	}
	
	public ScanTaskHandler getScanTaskHandler() {
		return scanTaskHandler;
	}

	@Override
	public synchronized void onScanTaskHandlerMessage(ScanTask scanTask, String message) {
	}

	@Override
	public synchronized void onScanTaskHandlerDone() {
	}
}
