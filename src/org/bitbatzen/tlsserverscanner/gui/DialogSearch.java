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
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.text.DefaultCaret;

import org.bitbatzen.tlsserverscanner.Util;
import org.bitbatzen.tlsserverscanner.scantask.Cert;
import org.bitbatzen.tlsserverscanner.scantask.ScanData;
import org.bitbatzen.tlsserverscanner.scantask.ScanTaskHandler;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
 

public class DialogSearch extends JDialog implements ActionListener {
	
	private class SearchResult {
		public HostListItem hostListItem;
		public List<String> resultTypes = new ArrayList<>();
	}
	
	private MainWindow mainWindow;
	
	private JEditorPane taResults;
	
	private JTextField tfSearch;

	private JCheckBox cbHostname;
	private JCheckBox cbCipherSuiteChosenByServer;
	private JCheckBox cbCertificate;
	private JCheckBox cbFullCertificateChain;
	private JCheckBox cbSupportedCipherSuites;
	private JCheckBox cbSupportedProtocols;
	
	private JButton buttonSearch;
	
	private JLabel labelSearchInfo;
	
	private List<SearchResult> results;
	
	
	public DialogSearch(MainWindow mainWindow) {
		super(mainWindow.getFrame(), "Full-Text Search", false);
		this.mainWindow = mainWindow;
		
		results = new ArrayList<>();
		
		final Dimension winSize = new Dimension(650, 550);
		final Dimension resultsSize = new Dimension(1000, 250);
		
		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		setResizable(false);
		setSize(winSize);
		
		// results area
		taResults = new JEditorPane();
		taResults.setFont(MainWindow.FONT_MEDIUM);
		taResults.setEditable(false);
		taResults.setContentType("text/html");
		DefaultCaret caret = (DefaultCaret) taResults.getCaret();
		caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);
		
		JScrollPane scrollPaneResults = new JScrollPane(taResults);
		scrollPaneResults.setPreferredSize(resultsSize);
		
	    JPanel panelSearchOptions = new JPanel();
	    BoxLayout layout = new BoxLayout(panelSearchOptions, BoxLayout.Y_AXIS);
	    panelSearchOptions.setLayout(layout);
	    panelSearchOptions.setBorder(BorderFactory.createEmptyBorder(15, 25, 25, 25));
		
		tfSearch = new JTextField();
		tfSearch.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
		tfSearch.setFont(MainWindow.FONT_MEDIUM);
		panelSearchOptions.add(tfSearch);
		
		panelSearchOptions.add(Box.createRigidArea(new Dimension(0, 5)));
		
		cbHostname = new JCheckBox("Hostname");
		cbHostname.setSelected(true);
		panelSearchOptions.add(cbHostname);
		
		cbCipherSuiteChosenByServer = new JCheckBox("Cipher Suite Chosen By Server");
		cbCipherSuiteChosenByServer.setSelected(true);
		panelSearchOptions.add(cbCipherSuiteChosenByServer);
		
		cbCertificate = new JCheckBox("Certificate");
		cbCertificate.setSelected(true);
		panelSearchOptions.add(cbCertificate);
		
		cbFullCertificateChain = new JCheckBox("Full Certificate Chain");
		cbFullCertificateChain.setSelected(true);
		panelSearchOptions.add(cbFullCertificateChain);
		
		cbSupportedCipherSuites = new JCheckBox("Supported Cipher Suites");
		cbSupportedCipherSuites.setSelected(true);
		panelSearchOptions.add(cbSupportedCipherSuites);
		
		cbSupportedProtocols = new JCheckBox("Supported Protocols");
		cbSupportedProtocols.setSelected(true);
		panelSearchOptions.add(cbSupportedProtocols);
		
		panelSearchOptions.add(Box.createRigidArea(new Dimension(0, 10)));
		 
		buttonSearch = new JButton("Search");
		buttonSearch.addActionListener(this);
		panelSearchOptions.add(buttonSearch);
		
		panelSearchOptions.add(Box.createRigidArea(new Dimension(0, 10)));
		
		labelSearchInfo = new JLabel(" ");
		panelSearchOptions.add(labelSearchInfo);
		
		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(panelSearchOptions, BorderLayout.NORTH);
		getContentPane().add(scrollPaneResults, BorderLayout.SOUTH);
		
        Dimension parentSize = mainWindow.getFrame().getSize(); 
        Point p = mainWindow.getFrame().getLocation(); 
        setLocation(p.x + parentSize.width / 2 - getWidth() / 2, p.y + 50);
	    setVisible(true);
	}
	
	private void search() {
		String search = tfSearch.getText();
		if (search.equals("")) {
			mainWindow.showMessageDialog("Error", "No text in search box!");
			return;
		}
		
		search = search.toLowerCase();
		results.clear();
		
		// hostnames
		if (cbHostname.isSelected()) {
			HostListItem[] hostListItems = mainWindow.getAreaHosts().getHostListItems();
			for (HostListItem host : hostListItems) {
				if (host.getHostWithPort().toLowerCase().contains(search)) {
					addResult(host, "Hostname");
				}
			}
		}
		
		ScanTaskHandler scanTaskHandler = mainWindow.getAreaControls().getScanTaskHandler();
		if (scanTaskHandler == null) {
			setResultsText();
			return;
		}
		
		HostListItem[] hostListItems = mainWindow.getAreaHosts().getHostListItems();
		
		for (HostListItem hostListItem : hostListItems) {
			if (hostListItem.getScanTask() == null) {
				continue;
			}
			
			ScanData sd = hostListItem.getScanTask().getScanData();
			
			// server-side chosen cipher suites
			if (cbCipherSuiteChosenByServer.isSelected()) {
				if (sd.cipherSuiteChosenByServer.toLowerCase().contains(search)) {
					addResult(hostListItem, "CipherSuiteChosenByServer");
				}				
			}
			
			// certificates
			if (cbCertificate.isSelected()) {
				if (sd.getCertAvailable()) {
					findInCertificate(hostListItem, search, sd.certs[0], "Certificate");
				}
			}

			// full certificate chain
			if (cbFullCertificateChain.isSelected()) {
				if (sd.getCertAvailable() && sd.certs.length > 1) {
					for (int i = 1; i < sd.certs.length; i++) {
						if (findInCertificate(hostListItem, search, sd.certs[i], "FullCertificateChain")) {
							break;
						}
					}
				}
			}
			
			// supported cipher suites
			if (cbSupportedCipherSuites.isSelected()) {
				HashMap<Integer, Boolean> cipherSuitesTested = sd.cipherSuitesTested;
				for (Map.Entry<Integer, Boolean> entry : cipherSuitesTested.entrySet()) {
				    if (entry.getValue()) {
				    	// (supported)
				    	String cipherSuite = scanTaskHandler.getCipherSuiteToTest(entry.getKey());
				    	if (cipherSuite.toLowerCase().contains(search)) {
				    		addResult(hostListItem, "SupportedCipherSuites");
				    		break;
				    	}
				    }
				}
			}
			
			// supported protocols
			if (cbSupportedProtocols.isSelected()) {
				HashMap<Integer, Boolean> protocolsTested = sd.protocolsTested;
				for (Map.Entry<Integer, Boolean> entry : protocolsTested.entrySet()) {
				    if (entry.getValue()) {
				    	// (supported)
				    	String protocol = scanTaskHandler.getProtocolToTest(entry.getKey());
				    	if (protocol.toLowerCase().contains(search)) {
				    		addResult(hostListItem, "SupportedProtocols");
				    		break;
				    	}
				    }
				}
			}
		}
		
		
		setResultsText();
	}
	
	private boolean findInCertificate(HostListItem hostListItem, String searchString, Cert cert, String resultType) {
		if (cert == null) {
			return false;
		}
		
		if (cert.getCert().toString().toLowerCase().contains(searchString)
				|| cert.getSubjectName().toLowerCase().contains(searchString)
				|| cert.getIssuerName().toLowerCase().contains(searchString)
				|| cert.getPublicKeyAlgorithmWithKeyLength().toLowerCase().contains(searchString)
				|| cert.getSignatureAlgorithm().toLowerCase().contains(searchString)) {
			
			addResult(hostListItem, resultType);
			return true;
		}
		else {
			List<String> oids = cert.getExtensionOIDsWithName();
			for (String oid : oids) {
				if (oid.toLowerCase().contains(searchString)) {
					addResult(hostListItem, resultType);
					return true;
				}
			}
		}
		
		return false;
	}
	
	private void addResult(HostListItem hostListItem, String resultType) {
		for (SearchResult sr : results) {
			if (sr.hostListItem == hostListItem) {
				sr.resultTypes.add(resultType);
				return;
			}
		}
		
		// create new entry
		SearchResult sr = new SearchResult();
		sr.hostListItem = hostListItem;
		sr.resultTypes.add(resultType);
		results.add(sr);
	}
	
	private void setResultsText() {
		if (results.size() == 0) {
			taResults.setText("");
		}
		else {
			StringBuilder sb = new StringBuilder();
			sb.append(Util.getFontFamilyTag(MainWindow.FONT_MEDIUM));
			
			for (SearchResult sr : results) {
				sb.append("<b>" + sr.hostListItem.getHostWithPortAndIndex() + "</b>");
				List<String> resultTypes = sr.resultTypes;
				sb.append("  (");	
				
				for (int i = 0; i < resultTypes.size(); i++) {
					String rt = resultTypes.get(i);
					if (i < resultTypes.size() -1) {
						sb.append(rt + ", ");					
					}
					else {
						sb.append(rt);
					}
				}
				
				sb.append(")");
				sb.append(Util.BR);
			}
			
			taResults.setText(sb.toString());
		}
		
		if (results.size() == 1) {
			labelSearchInfo.setText(results.size() + " hit");			
		}
		else {
			labelSearchInfo.setText(results.size() + " hits");
		}
	}

	@Override
	public void actionPerformed(ActionEvent arg0) {
		if (arg0.getSource() == buttonSearch) {
			search();
		}
	}
}
