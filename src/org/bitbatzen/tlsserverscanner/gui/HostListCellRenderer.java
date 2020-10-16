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
import java.awt.Component;
import java.awt.Font;

import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.ListCellRenderer;


public class HostListCellRenderer extends JLabel implements ListCellRenderer {
	
		
	public HostListCellRenderer() {
		setOpaque(true);
		setFont(MainWindow.FONT_BIG.deriveFont(Font.BOLD));
	}
	
	public Component getListCellRendererComponent(JList list, Object value,
			int index, boolean isSelected, boolean cellHasFocus) {
		
		HostListItem item = (HostListItem) value;
		setText(item.getText());
		
		if (isSelected) {
			setBackground(Color.DARK_GRAY);
			setForeground(Color.WHITE);
		} 
		else {
			setBackground(item.getBGColor());
			setForeground(Color.DARK_GRAY);
		}
		
		return this;	
	}
}

