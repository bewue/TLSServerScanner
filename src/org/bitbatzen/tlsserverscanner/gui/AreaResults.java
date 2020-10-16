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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.JEditorPane;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.text.DefaultCaret;

import org.bitbatzen.tlsserverscanner.Util;
import org.bitbatzen.tlsserverscanner.scantask.*;
import org.bitbatzen.tlsserverscanner.scantask.ScanTask.State;


public class AreaResults extends Area {
	
	private static final String H1_S = "<font size=5>";
	private static final String H1_E = "</font>"; 
	private static final String H2_S = "<font size=4><b>";
	private static final String H2_E = "</b></font>";
	private static final String BR = Util.BR;

	private JEditorPane textArea;
	private JScrollPane scrollPane;
	
	private ScanTask currentScanTask;
	
	private boolean plainTextEnabled;
	
	
	public AreaResults(MainWindow mainWindow) {
		super(mainWindow);
		
		panel.setLayout(null);
		textArea = new JEditorPane();
		textArea.setFont(MainWindow.FONT_MEDIUM);
		textArea.setEditable(false);
		
		setPlainTextEnabled(false);
		
		textArea.setBackground(MainWindow.COLOR_BG_RESULTS);
		
		DefaultCaret caret = (DefaultCaret) textArea.getCaret();
		caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);
		
		scrollPane = new JScrollPane(textArea);
		panel.add(scrollPane);
		
		currentScanTask = null;
	}
	
	@Override
	public void setPanelBounds(int x, int y, int width, int height) {
		super.setPanelBounds(x, y, width, height);
		
		textArea.setBounds(0, 0, width, height);
		scrollPane.setBounds(0, 0, width, height);		
	}
	
	private String getScanTaskStateMessage(ScanTask scanTask) {
		ScanTask.State state = ScanTask.getState(scanTask);
		if (state == ScanTask.State.ERROR) {
			return ScanTask.getStateTag(state) + " " + scanTask.getScanData().getErrorInfo();
		}
		else {
			return ScanTask.getStateTag(state);
		}
	}
	
	public void setPlainTextEnabled(boolean enabled) {
		plainTextEnabled = enabled;
		String contentType = plainTextEnabled ? "text/txt" : "text/html";
		textArea.setContentType(contentType);
		
		updateView();
	}
	
	public void updateView() {
		String result = "";
		if (mainWindow.getAreaControls().getStatisticSelected()) {
			result = getHTMLStatistic();
		}
		else {
			HostListItem item = mainWindow.getAreaHosts().getSelectedItem();
			if (item != null) {
				if (item.getScanTask() != null) {
					currentScanTask = item.getScanTask();
					result = getHTMLHostResults(currentScanTask);
				}
				else {
					result = getHTMLHostInfo(item);
				}				
			}
		}

		if (plainTextEnabled) {
			result = result.replace("<br>", Util.LF);
			result = result.replaceAll("\\<.*?>", "");
		}
		
		textArea.setText(result);
	}
	
	private String getHTMLHostInfo(HostListItem item) {
		String text = Util.getFontFamilyTag(MainWindow.FONT_MEDIUM) 
				+ H1_S + item.getHost() + ":" + item.getPort() + H1_E + BR
				+ Util.getBGColorTag(ScanTask.getStateColor(ScanTask.State.NONE)) + H2_S + getScanTaskStateMessage(item.getScanTask()) + H2_E + Util.COLOR_END_TAG
				+ Util.FONT_END_TAG;
		return text;
	}
	
	private void appendCipherSuites(StringBuilder sb, ScanTask scanTask, boolean supported) {
		HashMap<Integer, Boolean> map = scanTask.getScanData().cipherSuitesTested;
		for (Map.Entry<Integer, Boolean> entry : map.entrySet()) {
			String cipherSuite =  scanTask.getScanTaskHandler().getCipherSuiteToTest(entry.getKey());
		    if (entry.getValue() == supported) {
		    	sb.append(cipherSuite + BR);
		    }
		}
	}
	
	private void appendProtocols(StringBuilder sb, ScanTask scanTask, boolean supported) {
		HashMap<Integer, Boolean> map = scanTask.getScanData().protocolsTested;
		for (Map.Entry<Integer, Boolean> entry : map.entrySet()) {
			String cipherSuite =  scanTask.getScanTaskHandler().getProtocolToTest(entry.getKey());
		    if (entry.getValue() == supported) {
		    	sb.append(cipherSuite + BR);
		    }
		}
	}
	
	private String getHTMLHostResults(ScanTask scanTask) {
		if (scanTask == null) {
			return "";
		}
		
		ScanTask.State state = ScanTask.getState(scanTask);
		ScanData sd = scanTask.getScanData();
		StringBuilder sb = new StringBuilder(2500);
		
		sb.append(Util.getFontFamilyTag(MainWindow.FONT_MEDIUM));
		
		sb.append(H1_S + sd.getHostWithPort() + " (" + sd.getHostAddress() + ")" + H1_E + BR);
		sb.append(Util.getBGColorTag(ScanTask.getStateColor(state)) 
					+ H2_S + getScanTaskStateMessage(scanTask) + H2_E + BR + Util.COLOR_END_TAG);
		sb.append(BR);
		
		if (scanTask.getScanTaskHandler().getProtocolsToTestCount() > 0) {
			sb.append(H2_S + "<u>Supported Protocols:</u>" + H2_E + BR);
			appendProtocols(sb, scanTask, true);
			sb.append(BR);
			
			sb.append(H2_S + "<u>NOT Supported Protocols:</u>" + H2_E + BR);
			appendProtocols(sb, scanTask, false);
			sb.append(BR);
			sb.append(BR);
		}
		
		if (scanTask.getScanTaskHandler().getCipherSuitesToTestCount() > 0) {
			sb.append(H2_S + "<u>Supported Cipher Suites:</u>" + H2_E + BR);
			appendCipherSuites(sb, scanTask, true);
			sb.append(BR);
			
			sb.append(H2_S + "<u>NOT Supported Cipher Suites:</u>" + H2_E + BR);
			appendCipherSuites(sb, scanTask, false);
			sb.append(BR);
			sb.append(BR);
		}
		
		if (scanTask.getScanData().getCertAvailable() == false) {
			return sb.toString();
		}
		
		sb.append(H2_S + "<u>Cipher Suite Chosen By Server:</u>" + H2_E + BR);
		sb.append(sd.cipherSuiteChosenByServer + BR);
		sb.append(BR);
		
		sb.append(H2_S + "<u>Certificate Public Key Algorithm:</u>" + H2_E + BR);
		sb.append(sd.certs[0].getPublicKeyAlgorithmWithKeyLength() + BR);
		sb.append(BR);
		
		sb.append(H2_S + "<u>Certificate Signature Algorithm:</u>" + H2_E + BR);
		sb.append(sd.certs[0].getSignatureAlgorithm() + BR);
		sb.append(BR);
		
		sb.append(H2_S + "<u>Certificate Extensions:</u>" + H2_E + BR);
		List<String> oids = sd.certs[0].getExtensionOIDsWithName();
		for (String oid : oids) {
			sb.append(oid + BR);
		}
		sb.append(BR);
		
		return sb.toString();
	}
	
	private String getHTMLStatistic() {
		StringBuilder sb = new StringBuilder(2500);
		
		sb.append(Util.getFontFamilyTag(MainWindow.FONT_MEDIUM));
		
		sb.append(H1_S + "Statistic" + H1_E + BR);
		
		if (scanTaskHandler == null) {
			sb.append(H2_S + ScanTask.getStateTag(State.WAIT) + H2_E);
			return sb.toString();
		}
		
		ScanTask.State state = scanTaskHandler.getState();
		String colorTag = Util.getBGColorTag(ScanTask.getStateColor(state));
		String stateTag = ScanTask.getStateTag(state);
		sb.append(colorTag + H2_S + stateTag + H2_E + BR + Util.COLOR_END_TAG);
		sb.append(BR);
		sb.append(H2_S + "Hosts Completed (" + scanTaskHandler.getScansCompletedCount() + "/" + scanTaskHandler.getScanTasksCount() + ")" + H2_E + BR);
		if (scanTaskHandler.getScansFailedCount() == 0) {
			sb.append(H2_S + "Hosts Failed (" + scanTaskHandler.getScansFailedCount() + ")" + H2_E + BR);
		}
		else {
			sb.append(H2_S + "Hosts Failed " + Util.getBGColorTag(ScanTask.getStateColor(State.ERROR)) 
					+ "(" + scanTaskHandler.getScansFailedCount() + ")" + Util.COLOR_END_TAG + H2_E + BR);
		}
		sb.append(BR);
		
		if (scanTaskHandler.getProtocolsToTestCount() > 0) {
			sb.append(H2_S + "<u>Protocols:</u>" + H2_E + BR);
			StatisticUtil.appendProtocolStatistic(sb, scanTaskHandler);
			sb.append(BR);
		}
		
		if (scanTaskHandler.getCipherSuitesToTestCount() > 0) {
			sb.append(H2_S + "<u>Cipher Suites:</u>" + H2_E + BR);
			StatisticUtil.appendCipherSuiteStatistic(sb, scanTaskHandler);
			sb.append(BR);
		}
		
		if (scanTaskHandler.getCertCollectingEnabled() == false) {
			return sb.toString();
		}
		
		sb.append(H2_S + "<u>Cipher Suite Chosen By Server:</u>" + H2_E + BR);
		StatisticUtil.appendCipherSuiteChosenFromServerStatistic(sb, scanTaskHandler);
		sb.append(BR);
		
		sb.append(H2_S + "<u>Certificate Public Key Algorithm:</u>" + H2_E + BR);
		StatisticUtil.appendCertificatePubKeyAlgorithmStatistic(sb, scanTaskHandler);
		sb.append(BR);
		
		sb.append(H2_S + "<u>Certificate Public Key Algorithm (with key length):</u>" + H2_E + BR);
		StatisticUtil.appendCertificatePubKeyAlgorithmWithKeyLengthStatistic(sb, scanTaskHandler);
		sb.append(BR);
	
		sb.append(H2_S + "<u>Certificate Signature Algorithm:</u>" + H2_E + BR);
		StatisticUtil.appendCertificateSignatureAlgorithmStatistic(sb, scanTaskHandler);
		sb.append(BR);
	
		sb.append(H2_S + "<u>Certificate Extensions:</u>" + H2_E + BR);
		StatisticUtil.appendCertificateExtensionStatistic(sb, scanTaskHandler);
		sb.append(BR);			
	
		sb.append(H2_S + "<u>Certificate Root CAs (Organisation):</u>" + H2_E + BR);
		StatisticUtil.appendCertificateRootCAOrganisationStatistic(sb, scanTaskHandler);
		sb.append(BR);
	
		return sb.toString();	
	}
	
	@Override
	public synchronized void onScanTaskHandlerMessage(final ScanTask scanTask, String message) {
		if (currentScanTask == scanTask || mainWindow.getAreaControls().getStatisticSelected()) {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					updateView();
				}
			});
		}
	}
}
