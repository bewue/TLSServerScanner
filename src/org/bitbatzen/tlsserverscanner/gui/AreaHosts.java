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

import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JList;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.bitbatzen.tlsserverscanner.Util;


public class AreaHosts extends Area {
	
	private JScrollPane scrollPane;
	private JList<HostListItem> list;
	
	private HostListModel<HostListItem> listModel;
	
	
	public AreaHosts(final MainWindow mainWindow) {
		super(mainWindow);
		
		listModel = new HostListModel<HostListItem>();
		list = new JList<HostListItem>(listModel);
		list.setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
		list.setLayoutOrientation(JList.HORIZONTAL_WRAP);
		list.setVisibleRowCount(-1);
		list.setCellRenderer(new HostListCellRenderer());
		list.setBackground(MainWindow.COLOR_BG_HOSTS);
		
		list.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				mainWindow.getAreaControls().unselectStatisticButtons();
				mainWindow.getAreaResults().updateView();
			}
		});
		list.addFocusListener(new FocusListener() {
			@Override
			public void focusLost(FocusEvent e) {
			}
			@Override
			public void focusGained(FocusEvent e) {
				mainWindow.getAreaControls().unselectStatisticButtons();
				mainWindow.getAreaResults().updateView();
			}
		});
		
		scrollPane = new JScrollPane(list);
		panel.add(scrollPane);
	}
	
	public void addHost(String host, int port) {
		listModel.addElement(new HostListItem(host, port, listModel));
		updateAllHosts();
	}
	
	public void updateAllHosts() {
		for (int i = 0; i < listModel.size(); i++) {
			listModel.get(i).update();
		}
	}
	
	public HostListItem[] getHostListItems() {
		HostListItem[] hostItems = new HostListItem[listModel.size()];
		for (int i = 0; i < listModel.size(); i++) {
			hostItems[i] = listModel.get(i);
		}
		
		return hostItems;
	}
	
	public String getHostList() {
		StringBuilder sb = new StringBuilder(2000);
		for (int i = 0; i < listModel.size(); i++) {
			sb.append(listModel.get(i).getHostWithPort() + Util.LF);
		}
		
		return sb.toString();		
	}
	
	public int getHostListItemCount() {
		return listModel.size();
	}
	
	public List<HostListItem> getSelectedHosts() {
		List<HostListItem> hosts = new ArrayList<>();
        int[] selectedHosts = list.getSelectedIndices();
        for (int i = 0; i < selectedHosts.length; i++) {
            hosts.add(listModel.get(selectedHosts[i]));
        }
        
        return hosts;
	}
	
	public void removeSelectedHosts() {
        int[] selectedHosts = list.getSelectedIndices();
        for (int i = selectedHosts.length-1; i >= 0; i--) {
            listModel.removeElementAt(selectedHosts[i]);
        } 
        
        updateAllHosts();
        mainWindow.getAreaResults().updateView();
	}
	
	public void removeAllHosts() {
		listModel.clear();
        mainWindow.getAreaResults().updateView();		
	}
	
	public String checkHostDuplicates() {
		for (int i = 0; i < listModel.size(); i++) {
			String h1 = listModel.get(i).getHostWithPort();
			for (int k = 0; k < listModel.size(); k++) {
				String h2 = listModel.get(k).getHostWithPort();
				if (i != k && h1.equals(h2)) {
					return h1;
				}
			}
		}
		
		return null;
	}
	
	public void setPanelBounds(int x, int y, int width, int height) {
		panel.setBounds(x, y, width, height);
		
		list.setBounds(0, 0, width, height);
		list.setFixedCellWidth(width - BORDER_WIDTH - 1);
		
		scrollPane.setBounds(0, 0, width, height);	
	}
	
	public HostListItem getSelectedItem() {
		return (HostListItem) list.getSelectedValue();
	}
}
