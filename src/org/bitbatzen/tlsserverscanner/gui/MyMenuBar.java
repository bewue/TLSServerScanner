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

import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JCheckBoxMenuItem;
import javax.swing.JFileChooser;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;

import org.bitbatzen.tlsserverscanner.Util;
import org.bitbatzen.tlsserverscanner.gui.DialogSelectCipherSuites.DialogType;
import org.bitbatzen.tlsserverscanner.scantask.ScanTask.State;
import org.bitbatzen.tlsserverscanner.scantask.ScanTaskHandler;


public class MyMenuBar extends JMenuBar implements ActionListener {

	// menu file
	private JMenuItem itemSaveHostList;
	private JMenuItem itemLoadHostList;
	private JMenuItem itemQuit;
	
	// menu options
	private JMenuItem itemCertOptions;
	private JMenuItem itemSelectCipherSuites;
	private JMenuItem itemSelectProtocols;
	private JCheckBoxMenuItem itemCBDisableCertCollecting;
	private JCheckBoxMenuItem itemCBDisableCertVerification;
	
	// menu tools
	private JMenuItem itemViewCertificates;
	private JMenuItem itemSaveSelectedCertificates;
	private JMenuItem itemSearch;
	
	// menu info
	private JMenuItem itemAbout;
	
	private MainWindow mainWindow;
	
	private Font font;
	
	
	public MyMenuBar(MainWindow mainWindow) {
		this.mainWindow = mainWindow;
		font = new JMenuItem().getFont().deriveFont(13.0f);
		initMenuBar();
	}
	
	
	private void initMenuBar() {
		setBackground(MainWindow.COLOR_BG_MENUBAR);
		
		// file
		JMenu menuFile = createMenu("File");
		itemSaveHostList = createMenuItem("Save Hostlist");
		menuFile.add(itemSaveHostList);
		
		itemLoadHostList = createMenuItem("Load Hostlist");
		menuFile.add(itemLoadHostList);
		
		itemQuit = createMenuItem("Quit");
		menuFile.add(itemQuit);

		// options
		JMenu menuOptions = createMenu("Options");
		itemCertOptions = createMenuItem("Certificate");
		menuOptions.add(itemCertOptions);
		
		itemSelectCipherSuites = createMenuItem("Cipher Suites");
		menuOptions.add(itemSelectCipherSuites);
		
		itemSelectProtocols = createMenuItem("Protocols");
		menuOptions.add(itemSelectProtocols);

		// checkbox disable cert. collecting
		itemCBDisableCertCollecting = new JCheckBoxMenuItem("Disable Cert. Collecting");
		itemCBDisableCertCollecting.setFont(font);
		menuOptions.add(itemCBDisableCertCollecting);
		
		// checkbox disable cert. verification
		itemCBDisableCertVerification = new JCheckBoxMenuItem("Disable Cert. Verification");
		itemCBDisableCertVerification.setFont(font);
		menuOptions.add(itemCBDisableCertVerification);
		
		// tools
		JMenu menuTools = createMenu("Tools");
		itemViewCertificates = createMenuItem("View Certificates");
		menuTools.add(itemViewCertificates);
		
		itemSaveSelectedCertificates = createMenuItem("Save Selected Certificates");
		menuTools.add(itemSaveSelectedCertificates);
		
		itemSearch = createMenuItem("Full-Text Search");
		menuTools.add(itemSearch);
		
		// info
		JMenu menuInfo = createMenu("Info");
		itemAbout = createMenuItem("About");
		menuInfo.add(itemAbout);
		
		add(menuFile);
		add(menuOptions);
		add(menuTools);
		add(menuInfo);
	}
	
	public boolean getCertVerificationDisabled() {
		return itemCBDisableCertVerification.isSelected();
	}
	
	public boolean getCertCollectingDisabled() {
		return itemCBDisableCertCollecting.isSelected();
	}
	
	private JMenuItem createMenuItem(String name) {
		JMenuItem menuItem = new JMenuItem(name);
		menuItem.setFont(font);
		menuItem.addActionListener(this);
		return menuItem;
	}
	
	private JMenu createMenu(String name) {
		JMenu menu = new JMenu(name);
		menu.setFont(font);
		return menu;
	}
	
	private void onClickSaveHostList() {
		String title = "Save Hostlist";
		String hostlist = mainWindow.getAreaHosts().getHostList();
		if (hostlist.equals("")) {
			mainWindow.showMessageDialog(title, "Hostlist is empty!");
			return;
		}
		
		final JFileChooser fc = new JFileChooser(title);
		fc.setDialogTitle(title);
		fc.setApproveButtonText("Save");
		fc.setApproveButtonToolTipText("Save");
		int returnVal = fc.showOpenDialog(mainWindow.getFrame());
		
		if (returnVal == JFileChooser.APPROVE_OPTION) {
        	String prefix = fc.getSelectedFile().getName().toLowerCase().contains(".txt") ? "" : ".txt";
        	File file = new File(fc.getSelectedFile().getAbsolutePath() + prefix);
        	if (file.exists()) {
        		String text = "Replace " + file.getName() + " ?";
        		if (mainWindow.showConfirmDialog(title, text) == false) {
        			return;
        		}
        	}
        	
        	try {
        		Util.saveHostlistToFile(hostlist, file);
        	}
        	catch (Exception e) {
        		mainWindow.showMessageDialog(title, "<html>Failed to save file:" 
        				+ Util.BR + e.getMessage() + "</html>");
        	}
        	
        	mainWindow.showMessageDialog(title, "<html>Saved hostlist to:" 
        			+ Util.BR + Util.BR + file.getPath() + "</html>");
		}
	}
	
	private void onClickLoadHostList() {
		String title = "Load Hostlist";
   		if (mainWindow.getAreaHosts().getHostListItemCount() > 0) {
			if (mainWindow.showConfirmDialog(title, "The existing hostlist will be replaced!") == false) {
				return;
			}
		}
		
		final JFileChooser fc = new JFileChooser(title);
		fc.setDialogTitle(title);
		int returnVal = fc.showOpenDialog(mainWindow.getFrame());
		
		if (returnVal == JFileChooser.APPROVE_OPTION) {
        	List<String> hostlist = new ArrayList<>();
        	
        	try {
        		int result = Util.loadHostlistFromFile(hostlist, fc.getSelectedFile());
        		if (result != 0) {
            		mainWindow.showMessageDialog(title, "<html>Syntax error in line " + result 
            				+ Util.BR + Util.BR + "(syntax: host:port)</html>");	
            		return;        			
        		}
        	}
        	catch (Exception e) {
        		mainWindow.showMessageDialog(title, "<html>Failed to read file:" 
        				+ Util.BR + e.getMessage() + "</html>");
        		return;
        	}
        		
    		if (hostlist.size() == 0) {
    			mainWindow.showMessageDialog(title, "Hostlist is empty!");
    			return;
    		}
    		
    		if (hostlist.size() > 200) {
        		mainWindow.showMessageDialog(title, "<html>" + hostlist.size() + " hosts to load!" 
        				+ Util.BR + "This could take a few seconds.</html>");
    		}
    					
    		mainWindow.getAreaHosts().removeAllHosts();
    		
    		for (String h : hostlist) {
    			String host = Util.extractHost(h);
    			int port = Util.extractPort(h);
    			mainWindow.getAreaHosts().addHost(host, port);
    		}
    		
    		mainWindow.showMessageDialog(title, "Added " + hostlist.size() + " hosts!");
		}	
	}
	
	private void onClickViewCertificate() {
		HostListItem host = mainWindow.getAreaHosts().getSelectedItem();
		if (host == null) {
			mainWindow.showMessageDialog("Certificates", "No host selected!");
			return;
		}
		else if (host.getScanTask() == null || host.getScanTask().getScanData().getCertAvailable() == false) {
			mainWindow.showMessageDialog("Certificates", "No certificate found!");
			return;
		}
		
		String title = "Certificates (" + host.getHostWithPort() + ")";
		new DialogViewCertificates(mainWindow, title, host);
	}
	
	private void onClickQuit() {
		if (mainWindow.showConfirmDialog("Quit", "<html>Unsaved data will be lost!<br>Quit?</html>")) {
			mainWindow.getFrame().dispose();
		}
	}
	
	private void onClickCertOptions() {
		new DialogSelectCipherSuites(mainWindow, DialogType.CIPHER_SUITES_FOR_COLLECTING_CERT, "Certifcate");
	}
	
	private void onClickSelectCipherSuitesToTest() {
		new DialogSelectCipherSuites(mainWindow, DialogType.CIPHER_SUITES_TO_TEST, "Cipher Suites");
	}
	
	private void onClickSelectProtocols() {
		new DialogSelectProtocols(mainWindow);
	}
	
	private void onClickSaveSelectedCertificates() {
		String title = "Save Selected Certificates";
		List<HostListItem> hosts = mainWindow.getAreaHosts().getSelectedHosts();
		if (hosts.isEmpty()) {
			mainWindow.showMessageDialog(title, "No host selected!");
			return;
		}
		
		int certificateCount = 0;
		int allCertificatesCount = 0;
		for (HostListItem host : hosts) {
			if (host.getScanTask() != null && host.getScanTask().getScanData().getCertAvailable()) {
				certificateCount++;
				allCertificatesCount += host.getScanTask().getScanData().certs.length;
			}
		}		
		if (certificateCount == 0) {
			mainWindow.showMessageDialog(title, "No certificates found!");
			return;
		}
		else {
			String hostString = certificateCount == 1 ? "host" : "hosts";
			mainWindow.showMessageDialog(title, "Found " + allCertificatesCount + " certificates!"
					+ " (" + certificateCount + " " + hostString + " selected)");
		}
		
		
		final JFileChooser fc = new JFileChooser();
		fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		fc.setDialogTitle("Select a Folder");
		fc.setApproveButtonText("Save");
		fc.setApproveButtonToolTipText("Save to Folder");
		int returnVal = fc.showOpenDialog(mainWindow.getFrame());
		
		if (returnVal == JFileChooser.APPROVE_OPTION) {
        	File directory = fc.getSelectedFile();
        	
        	try {
        		Util.saveCertificatesToDirectory(hosts, directory);
        	}
        	catch (Exception e) {
        		mainWindow.showMessageDialog(title, "<html>Failed to save certificates:" 
        				+ Util.BR + e.getMessage() + "</html>");
        	}
        	
        	mainWindow.showMessageDialog(title, "<html>Saved certificates to:" 
        			+ Util.BR + Util.BR + directory.getPath() + "</html>");
		}
	}
	
	private void onClickSearch() {
		ScanTaskHandler scanTaskHandler = mainWindow.getAreaControls().getScanTaskHandler();
		if (mainWindow.getAreaHosts().getHostListItemCount() == 0) {
			mainWindow.showMessageDialog(itemSearch.getText(), "Hostlist is empty!");
			return;
		}
		else if (scanTaskHandler != null && scanTaskHandler.getState() == State.RUNNING) {
			mainWindow.showMessageDialog(itemSearch.getText(), "You have to finish the current scan!");
			return;
		}
		
		new DialogSearch(mainWindow);
	}
	
	private void onClickAbout() {
		mainWindow.showAppInfoDialog(false);
	}
	
	@Override
	public void actionPerformed(ActionEvent arg0) {
		if (arg0.getSource() == itemSaveHostList) {
			onClickSaveHostList();
		}
		else if (arg0.getSource() == itemLoadHostList) {
			onClickLoadHostList();
		}		
		else if (arg0.getSource() == itemSaveSelectedCertificates) {
			onClickSaveSelectedCertificates();
		}
		else if (arg0.getSource() == itemQuit) {
			onClickQuit();
		}
		else if (arg0.getSource() == itemCertOptions) {
			onClickCertOptions();
		}
		else if (arg0.getSource() == itemSelectCipherSuites) {
			onClickSelectCipherSuitesToTest();
		}
		else if (arg0.getSource() == itemSelectProtocols) {
			onClickSelectProtocols();
		}
		else if (arg0.getSource() == itemViewCertificates) {
			onClickViewCertificate();
		}
		else if (arg0.getSource() == itemSearch) {
			onClickSearch();
		}
		else if (arg0.getSource() == itemAbout) {
			onClickAbout();
		}
	}

}
