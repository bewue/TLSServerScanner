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

import javax.swing.DefaultListModel;
import javax.swing.JDialog;
import javax.swing.JEditorPane;
import javax.swing.JList;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.text.DefaultCaret;

import org.bitbatzen.tlsserverscanner.Util;
import org.bitbatzen.tlsserverscanner.scantask.Cert;
import org.bitbatzen.tlsserverscanner.scantask.ScanData;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Point;
import java.text.SimpleDateFormat;
import java.util.List;
 

public class DialogViewCertificates extends JDialog {
	
	private static final String BR = Util.BR;
	private static final String H2_S = "<font size=4><b>";
	private static final String H2_E = "</b></font>";
	
	private MainWindow mainWindow;
	
	private SimpleDateFormat dateFormat;
	
	private JList<String> certificatesList;
	private JEditorPane textArea;
	
	private HostListItem host;
	
	
	public DialogViewCertificates(MainWindow mainWindow, String title, HostListItem host) {
		super(mainWindow.getFrame(), title, false);
		this.mainWindow = mainWindow;
		this.host = host;
		
		dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		
		final Dimension winSize = new Dimension(800, 600);
		final Dimension resultsSize = new Dimension(550, 600);
		final Dimension certListSize = new Dimension(240, 600);
		
		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		setResizable(false);
		setSize(winSize);
		
		// results area
		textArea = new JEditorPane();
		textArea.setFont(MainWindow.FONT_MEDIUM);
		textArea.setEditable(false);
		DefaultCaret caret = (DefaultCaret) textArea.getCaret();
		caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);

		JScrollPane scrollPaneResults = new JScrollPane(textArea);
		scrollPaneResults.setPreferredSize(resultsSize);
		
		// certificates list
		DefaultListModel<String> listModel = new DefaultListModel<String>();
		certificatesList = new JList<String>(listModel);
		certificatesList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		certificatesList.setLayoutOrientation(JList.VERTICAL_WRAP);
		certificatesList.setVisibleRowCount(-1);
		certificatesList.setBackground(new Color(220, 220, 220));
		JScrollPane scrollPaneCertList = new JScrollPane(certificatesList);
		scrollPaneCertList.setPreferredSize(certListSize);
		
		certificatesList.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				showCertificate(certificatesList.getSelectedIndex());
			}
		});

		String[] certNames = host.getScanTask().getScanData().getCertNames();
		for (String name : certNames) {
			listModel.addElement(name);
		}
		
		certificatesList.setSelectedIndex(0);
		
		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(scrollPaneCertList, BorderLayout.WEST);
		getContentPane().add(scrollPaneResults, BorderLayout.EAST);
		
        Dimension parentSize = mainWindow.getFrame().getSize(); 
        Point p = mainWindow.getFrame().getLocation(); 
        setLocation(p.x + parentSize.width / 2 - getWidth() / 2, p.y + 50);
	    setVisible(true);
	}
	
	private void showCertificate(int index) {
		String result = getHTMLCertificateData(host, host.getScanTask().getScanData().certs[index]);
		
		boolean plainTextEnabled = false;
		String contentType = plainTextEnabled ? "text/txt" : "text/html";
		textArea.setContentType(contentType);
		if (plainTextEnabled) {
			result = result.replace("<br>", Util.LF);
			result = result.replaceAll("\\<.*?>", "");
		}
		
		textArea.setText(result);
	}
	
	private String getHTMLCertificateData(HostListItem host, Cert cert) {
		ScanData sd = host.getScanTask().getScanData();
		StringBuilder sb = new StringBuilder(2500);
		
		sb.append(Util.getFontFamilyTag(MainWindow.FONT_MEDIUM));
		
		sb.append(H2_S + "Certificate Format: " + H2_E + BR);
		sb.append("Type: " + cert.getType() + BR);
		sb.append("Version: " + cert.getVersion() + BR);
		sb.append(BR);
		
		String certVerification = "";
		if (host.getScanTask().getScanTaskHandler().getCertAndHostnameVerificationEnabled() == false) {
			certVerification = H2_S + Util.getBGColorTag(Color.RED) + "(certificate verification is disabled!)" + Util.COLOR_END_TAG + H2_E;
		}
		
		boolean isSelfSigned = sd.getIsCertSelfSigned();
		String selfSignedString = isSelfSigned ? "(self-signed) " : "";
		sb.append(H2_S + "Subject: " + selfSignedString + H2_E + certVerification + BR);
		sb.append(Cert.formatCertName2(cert.getSubjectName()));
		sb.append(BR);
		
		sb.append(H2_S + "Issuer: " + selfSignedString + H2_E + BR);
		sb.append(Cert.formatCertName2(cert.getIssuerName()));
		sb.append(BR);
		
		sb.append(H2_S + "Not Before: " + H2_E + BR);
		sb.append(dateFormat.format(cert.getNotBefore()) + BR);
		sb.append(BR);
		
		sb.append(H2_S + "Not After: " + H2_E + BR);
		sb.append(dateFormat.format(cert.getNotAfter()) + BR);
		sb.append(BR);
		
		String[] alternativeNames = cert.getSubjectAlternativeNames();
		if (alternativeNames != null && alternativeNames.length > 0) {
			sb.append(H2_S + "Subject Alternative Names:" + H2_E + BR);
			for (String s : alternativeNames) {
				sb.append(s + BR);
			}
			sb.append(BR);
		}
		
		sb.append(H2_S + "Extensions: " + H2_E + BR);
		List<String> oids = cert.getExtensionOIDsWithName();
		for (String oid : oids) {
			sb.append(oid + BR);
		}
		sb.append(BR);
		
		sb.append(H2_S + "Public Key Algorithm: " + H2_E + BR);
		sb.append(cert.getPublicKeyAlgorithmWithKeyLength() + BR);
		sb.append(BR);
		
		sb.append(H2_S + "Signature Algorithm: " + H2_E + BR);
		sb.append(cert.getSignatureAlgorithm() + BR);
		sb.append(BR);
		
		return sb.toString();
	}
}
