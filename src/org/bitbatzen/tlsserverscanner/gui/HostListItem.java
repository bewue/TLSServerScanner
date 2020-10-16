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

import java.awt.Color;

import javax.swing.SwingUtilities;

import org.bitbatzen.tlsserverscanner.scantask.IScanTaskListener;
import org.bitbatzen.tlsserverscanner.scantask.ScanTask;


public class HostListItem implements IScanTaskListener {
	
	private String host;
	private int port;
	
	private int index;
	
	private String text;
	
	private Color bgColor;
	
	private ScanTask scanTask;
	private HostListModel<HostListItem> listModel;
	
	
	public HostListItem(String host, int port, HostListModel<HostListItem> listModel) {
		this.host = host;
		this.port = port;
		this.listModel = listModel;
		
		scanTask = null;
		bgColor = MainWindow.COLOR_BG_HOSTS;

		setText(ScanTask.getStateTag(ScanTask.State.NONE));
		
		index = listModel.getIndex(this);
		listModel.update(index);
	}
	
	public String getHost() {
		return host;
	}
	
	public int getPort() {
		return port;
	}
	
	public String getHostWithPort() {
		return host + ":" + port;
	}
	
	public String getHostWithPortAndIndex() {
		return getIndexString() + " " + getHostWithPort();
	}
	
	public void setScanTask(ScanTask scanTask) {
		this.scanTask = scanTask;
		scanTask.addListener(this);
	}
	
	public String getText() {
		return text;
	}
	
	public ScanTask getScanTask() {
		return scanTask;
	}
	
	public Color getBGColor() {
		return bgColor;
	}
	
	public String getIndexString() {
		int hostCount = Integer.toString(listModel.size()).length();
		int indexCount = Integer.toString(index + 1).length();
		String spacer = "";
		for (int i = 0; i < hostCount - indexCount; i++) {
			spacer += "0";
		}
		
		return "[" + spacer + (index + 1) + "]";
	}
	
	public void update() {
		ScanTask.State state = ScanTask.getState(scanTask);
		bgColor = ScanTask.getStateColor(state);
		index = listModel.getIndex(this);
		setText(ScanTask.getStateTag(state));
		
		listModel.update(index);
	}
	
	private void setText(String state) {
		text = getIndexString() + state + " " + getHostWithPort();
	}

	@Override
	public synchronized void onScanTaskStateChanged(ScanTask scanTask, String message) {
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				update();
			}
		});
	}
}
