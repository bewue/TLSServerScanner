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
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Point;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.util.Locale;

import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.UIManager;

import org.bitbatzen.tlsserverscanner.Util;


public class MainWindow implements ComponentListener {
	
	public static final Font FONT_LOG 		= new Font("Monospaced", Font.PLAIN, 13);
	public static final Font FONT_SMALL 	= new Font("Monospaced", Font.PLAIN, 12);
	public static final Font FONT_MEDIUM	= new Font("Monospaced", Font.PLAIN, 14);
	public static final Font FONT_BIG 		= new Font("Monospaced", Font.PLAIN, 16);
	public static final Font FONT_HUGE 		= new Font("Monospaced", Font.PLAIN, 18);
	
	public static final Color COLOR_HINT 			= Color.BLUE;
	public static final Color COLOR_DIALOG_HEADER 	= Color.DARK_GRAY;
	
	public static final Color COLOR_BG_RESULTS 		= new Color(255, 255, 255);
	public static final Color COLOR_BG_HOSTS 		= new Color(255, 255, 255);
	public static final Color COLOR_BG_LOG 			= new Color(220, 220, 220);
	public static final Color COLOR_BG_CONTROLS		= new Color(220, 220, 220);
	public static final Color COLOR_BG_MENUBAR		= new Color(220, 220, 220);
	
	public static final int HOST_AREA_WIDTH = 350;

	private AreaLog areaLog;
	private AreaControls areaControls;
	private AreaHosts areaHosts;
	private AreaResults areaResults;
	private MyMenuBar myMenuBar;
	
	private JPanel containerPanel;
	
	private JFrame frame;

	
	public MainWindow() {
		areaControls = new AreaControls(this);
		areaLog = new AreaLog(this);
		areaHosts = new AreaHosts(this);
		areaResults = new AreaResults(this);
		
		initWindow();
		
		showAppInfoDialog(true);
	}
	
	public AreaLog getAreaLog() {
		return areaLog;
	}
	
	public AreaControls getAreaControls() {
		return areaControls;
	}

	public AreaHosts getAreaHosts() {
		return areaHosts;
	}
	
	public AreaResults getAreaResults() {
		return areaResults;
	}
	
	public MyMenuBar getMyMenuBar() {
		return myMenuBar;
	}
	
	public JFrame getFrame() {
		return frame;
	}
	
	private void initWindow() {
		Locale.setDefault(java.util.Locale.ENGLISH);
		JComponent.setDefaultLocale(Locale.ENGLISH);
		UIManager.put("OptionPane.messageFont", FONT_MEDIUM);
		
		frame = new JFrame(Util.T_APP_NAME);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.addComponentListener(this);
		frame.setSize(1200, 850);
		
		containerPanel = new JPanel();
		frame.getContentPane().add(containerPanel);
		
		containerPanel.add(areaControls.getPanel());
		containerPanel.add(areaHosts.getPanel());
		containerPanel.add(areaResults.getPanel());
		containerPanel.add(areaLog.getPanel());
		
		myMenuBar = new MyMenuBar(this);
		frame.setJMenuBar(myMenuBar);
		
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
	}
	
	public void setDefaultPopupPosition(JDialog popup) {
        Dimension parentSize = frame.getSize(); 
        Point p = frame.getLocation(); 
        popup.setLocation(p.x + parentSize.width / 2 - popup.getWidth() / 2, p.y + 150);
	}
	
	public void showAppInfoDialog(boolean isIntro) {
		StringBuilder sb = new StringBuilder();
		
		sb.append(Util.T_APP_NAME + " " + Util.T_APP_VERSION + Util.LF);
		sb.append(Util.LF);
		
		if (!isIntro) {
			sb.append(Util.T_APP_NAME + " is licensed under the " + Util.T_APP_LICENSE + "." + Util.LF);
			sb.append(Util.LF);
		}
		
		sb.append("WARNING: Scanning can generate undesired load on the servers!" + Util.LF);
		sb.append("DO NOT use this program if you are unsure about the consequences!" + Util.LF);
		sb.append(Util.LF);
		
		if (!isIntro) {
			sb.append("Developer: " + Util.T_AUTOR + Util.LF);
			sb.append("Contact: " + Util.T_CONTACT_EMAIL + Util.LF);
			sb.append("Code: " + Util.T_CODE_URL + Util.LF);
		}
		
		showMessageDialog("About", sb.toString());
	}
	
	public boolean showConfirmDialog(String title, String text) {
		DialogConfirm dialog = new DialogConfirm(this, title, text);
		return dialog.showDialog();
	}
	
	public void showMessageDialog(String title, String text) {
		DialogMessage dialog = new DialogMessage(this, title, text);
		dialog.showDialog();
	}
	
	@Override
	public void componentResized(ComponentEvent e) {
		int cWidth = containerPanel.getWidth();
		int cHeight = containerPanel.getHeight();
		
		final int controlAreaHeight = 40;
		final int logAreaHeight = 200;
		
		areaControls.setPanelBounds(0, 0, cWidth, controlAreaHeight);
		
		areaLog.setPanelBounds(0, cHeight - logAreaHeight, cWidth, logAreaHeight);
		
		int centerAreasHeight = cHeight - logAreaHeight - controlAreaHeight;
		areaHosts.setPanelBounds(0, controlAreaHeight, HOST_AREA_WIDTH, centerAreasHeight);
		
		int resultsAreaWidth = cWidth - HOST_AREA_WIDTH;
		areaResults.setPanelBounds(HOST_AREA_WIDTH, controlAreaHeight, resultsAreaWidth, centerAreasHeight);
	}

	@Override
	public void componentHidden(ComponentEvent e) {
	}

	@Override
	public void componentMoved(ComponentEvent e) {
	}

	@Override
	public void componentShown(ComponentEvent e) {
	}
}
