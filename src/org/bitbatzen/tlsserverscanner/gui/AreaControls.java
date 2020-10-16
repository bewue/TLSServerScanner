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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JToggleButton;
import javax.swing.SwingUtilities;

import org.bitbatzen.tlsserverscanner.Util;
import org.bitbatzen.tlsserverscanner.gui.DialogSelectCipherSuites.DialogType;
import org.bitbatzen.tlsserverscanner.scantask.*;


public class AreaControls extends Area implements ActionListener {
	
	private static final int SPACER_SMALL = 5;
	
	private JButton buttonNewHost;
	private JButton buttonDeleteHosts;
	
	private JButton buttonStartScan;
	private JButton buttonStopScan;
	
	private JToggleButton buttonStatistic;
	
	private JToggleButton buttonPlainText;
//	private JButton buttonClearLog;
	
	
	public AreaControls(MainWindow mainWindow) {
		super(mainWindow);
		
		panel.setBackground(MainWindow.COLOR_BG_CONTROLS);
		
	    BoxLayout layout = new BoxLayout(panel, BoxLayout.X_AXIS);
	    panel.setLayout(layout);
	    panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		
		// button new host
		buttonNewHost = new JButton("+");
		buttonNewHost.addActionListener(this);
		panel.add(buttonNewHost);
		panel.add(Box.createRigidArea(new Dimension(SPACER_SMALL, 0)));
		// button delete host(s)		
		buttonDeleteHosts = new JButton("-");
		buttonDeleteHosts.addActionListener(this);
		panel.add(buttonDeleteHosts);
		
//		panel.add(Box.createRigidArea(new Dimension(57, 0)));
		
		// button statistic
		buttonStatistic = new JToggleButton("Statistic");
		buttonStatistic.addActionListener(this);
		panel.add(buttonStatistic);
		
//		panel.add(Box.createRigidArea(new Dimension(50, 0)));
		
		// button start scan
		buttonStartScan = new JButton("Start");
		buttonStartScan.addActionListener(this);
		panel.add(buttonStartScan);
		panel.add(Box.createRigidArea(new Dimension(SPACER_SMALL, 0)));
		// button stop scan
		buttonStopScan = new JButton("Stop");
		buttonStopScan.addActionListener(this);
		panel.add(buttonStopScan);
		
		// button plain text
		buttonPlainText = new JToggleButton("Plain Text");
		buttonPlainText.addActionListener(this);
		panel.add(buttonPlainText);
		
		updateGUIElements();
	}
	
	private void onClickNewHost() {
		new DialogNewHost(mainWindow);
	}
	
	private void onClickDeleteHosts() {
		if (mainWindow.getAreaHosts().getHostListItemCount() == 0) {
			mainWindow.showMessageDialog("Delete Hosts(s)", "No host(s) to delete!");
			return;
		}
		else if (mainWindow.getAreaHosts().getSelectedItem() == null) {
			mainWindow.showMessageDialog("Delete Hosts(s)", "No host selected!");
			return;
		}
		else if (mainWindow.showConfirmDialog("Delete Host(s)", "Delete selected host(s)?")) {
			mainWindow.getAreaHosts().removeSelectedHosts();
		}
	}
	
	private void onClickStartScan() {
		HostListItem[] hostListItems = mainWindow.getAreaHosts().getHostListItems();
		if (hostListItems.length == 0) {
			mainWindow.showMessageDialog("Start Scan", "Hostlist is empty!");
			return;
		}
		else {
			String duplicate = mainWindow.getAreaHosts().checkHostDuplicates();
			if (duplicate != null) {
				String text = "<html>Warning:" + Util.BR + Util.BR + "Duplicate in list:" + Util.BR + duplicate + "</html>";
				if (mainWindow.showConfirmDialog("Start Scan", text) == false) {
					return;
				}
			}
		}
		
		boolean certCollectingDisabled = mainWindow.getMyMenuBar().getCertCollectingDisabled();
		boolean certVerificationDisabled = mainWindow.getMyMenuBar().getCertVerificationDisabled();
		
		String startScanPopupText = getStartScanPopupText(certCollectingDisabled, certVerificationDisabled);
		if (mainWindow.showConfirmDialog("Start Scan", startScanPopupText) == false) {
			return;
		}
		
		ScanTaskHandler scanTaskHandler = new ScanTaskHandler();
		scanTaskHandler.init(certCollectingDisabled == false, certVerificationDisabled == false);
		scanTaskHandler.setCipherSuitesForCollectingCert(DialogSelectCipherSuites.getSelectedCipherSuites(DialogType.CIPHER_SUITES_FOR_COLLECTING_CERT));
		scanTaskHandler.setCipherSuitesToTest(DialogSelectCipherSuites.getSelectedCipherSuites(DialogType.CIPHER_SUITES_TO_TEST));
		scanTaskHandler.setProtocolsToTest(DialogSelectProtocols.getSelectedProtocols());
		setScanTaskHandler(scanTaskHandler);
		
		// create the ScanTasks
		for (HostListItem hli : hostListItems) {
			ScanTask scanTask = new ScanTask(hli.getHost(), hli.getPort());
			scanTaskHandler.addScanTask(scanTask);
			hli.setScanTask(scanTask);
		}
		
		mainWindow.getAreaHosts().setScanTaskHandler(scanTaskHandler);
		mainWindow.getAreaLog().setScanTaskHandler(scanTaskHandler);
		mainWindow.getAreaResults().setScanTaskHandler(scanTaskHandler);
		
		mainWindow.getAreaResults().updateView();
		mainWindow.getAreaHosts().updateAllHosts();
		
		scanTaskHandler.startScans();
		
		updateGUIElements();
	}
	
	private void onClickStopScan() {
		if (mainWindow.showConfirmDialog("Stop Scan", "Stop the current scan?")) {
			scanTaskHandler.stopScans();	
			updateGUIElements();
		}
	}
	
	private void onClickStatistic() {
		mainWindow.getAreaResults().updateView();
	}
	
	private void onClickPlainText() {
		mainWindow.getAreaResults().setPlainTextEnabled(buttonPlainText.isSelected());
	}
	
//	private void onClickClearLog() {
//		mainWindow.getAreaLog().clearLog();
//	}
	
	public void unselectStatisticButtons() {
		buttonStatistic.setSelected(false);
	}
	
	public boolean getStatisticSelected() {
		return buttonStatistic.isSelected();
	}
	
	public void updateGUIElements() {
		boolean scanRunning = (scanTaskHandler != null && scanTaskHandler.getScansRunning());
		
		buttonNewHost.setEnabled(!scanRunning);
		buttonDeleteHosts.setEnabled(!scanRunning);

		buttonStartScan.setEnabled(!scanRunning);
		buttonStopScan.setEnabled(scanRunning);
	}
	
	private String getStartScanPopupText(boolean certCollectingDisabled, boolean certVerificationDisabled) {
		String hostString = (mainWindow.getAreaHosts().getHostListItemCount() == 1) ? "host" : "hosts";
		String certCollectingString = certCollectingDisabled ? "- Certificate collecting is disabled!"
				: "- Certificate collecting is enabled!";
		String certVerString = certVerificationDisabled ? Util.getBGColorTag(Color.RED) + "DISABLED!" + Util.COLOR_END_TAG 
				: "enabled!";
		
		int cipherSuitesToTestCount = DialogSelectCipherSuites.getSelectedCipherSuites(DialogType.CIPHER_SUITES_TO_TEST).size(); 
		
		String text = "<html>"
				+ "- " + mainWindow.getAreaHosts().getHostListItemCount() + " " + hostString + " to scan!"
				+ "<br>- " + cipherSuitesToTestCount + " cipher suites to test!"
				+ "<br>- " + DialogSelectProtocols.getSelectedProtocols().size() + " protocol versions to test!"
				+ "<br>" + certCollectingString
				+ "<br>- Certificate verification is " + certVerString
				+ "<br><br>Current scan data will be lost!"
				+ "<br>Start scan?</html>";
		
		return text;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == buttonNewHost) {
			onClickNewHost();
		}
		else if (e.getSource() == buttonDeleteHosts) {
			onClickDeleteHosts();
		}
		else if (e.getSource() == buttonStartScan) {
			onClickStartScan();
		}
		else if (e.getSource() == buttonStopScan) {
			onClickStopScan();
		}
		else if (e.getSource() == buttonStatistic) {
			onClickStatistic();
		}
		else if (e.getSource() == buttonPlainText) {
			onClickPlainText();
		}
//		else if (e.getSource() == buttonClearLog) {
//			onClickClearLog();
//		}
	}
	
	@Override
	public void setPanelBounds(int x, int y, int width, int height) {
		super.setPanelBounds(x, y, width, height);
		
		buttonNewHost.setBounds(buttonNewHost.getX(), buttonNewHost.getY(), 45, buttonNewHost.getHeight());
		buttonDeleteHosts.setBounds(buttonDeleteHosts.getX(), buttonDeleteHosts.getY(), 45, buttonDeleteHosts.getHeight());
		
		int posXButtonStatistic = ((MainWindow.HOST_AREA_WIDTH - buttonDeleteHosts.getX() + buttonStatistic.getWidth() / 2)) / 2;
		buttonStatistic.setBounds(posXButtonStatistic, buttonStatistic.getY(), buttonStatistic.getWidth(), buttonStatistic.getHeight());
		
		buttonStartScan.setBounds(MainWindow.HOST_AREA_WIDTH, buttonStartScan.getY(), buttonStartScan.getWidth(), buttonStartScan.getHeight());
		int posXButtonStopScan = buttonStartScan.getX() + buttonStartScan.getWidth() + SPACER_SMALL;
		buttonStopScan.setBounds(posXButtonStopScan, buttonStopScan.getY(), buttonStopScan.getWidth(), buttonStopScan.getHeight());
		
		int posXButtonPlainText = Math.max(width - buttonPlainText.getWidth() - 5, buttonStopScan.getX() + buttonStopScan.getWidth() + 20);
		buttonPlainText.setBounds(posXButtonPlainText, buttonPlainText.getY(), buttonPlainText.getWidth(), buttonPlainText.getHeight());		
	}
	
	@Override
	public synchronized void onScanTaskHandlerDone() {
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				updateGUIElements();
			}
		});		
	}
}
