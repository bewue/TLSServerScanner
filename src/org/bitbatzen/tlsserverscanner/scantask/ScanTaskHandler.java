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

package org.bitbatzen.tlsserverscanner.scantask;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import javax.net.ssl.SSLSocketFactory;

import org.bitbatzen.tlsserverscanner.Util;
import org.bitbatzen.tlsserverscanner.scantask.ScanTask.State;


public class ScanTaskHandler implements IScanTaskListener {

	private int maxParallelScans = 10;
	
	private long scanStartTime;

	private List<ScanTask> scanTasks;
	
	private List<String> cipherSuitesForCollectingCert;
	private List<String> cipherSuitesToTest;
	private List<String> protocolsToTest;
	
	private boolean certAndHostnameVerificationEnabled;
	private boolean certCollectingEnabled;
	private SSLSocketFactory sslSocketFactory;
	
	private SimpleDateFormat logDateFormat;
	
	private List<IScanTaskHandlerListener> listeners;
	
	private Timer finishMessageDelayTimer;
	
	private final static int FINISH_MESSAGE_DELAY_TIME = 500;
	
	private boolean scansStarted;
	private boolean scansStoppedByUser;
	
	private static final String LOG_PREFIX = "+++++++";
	
	
	public ScanTaskHandler() {
		scanStartTime = 0;
		scanTasks = new ArrayList<>();
		cipherSuitesForCollectingCert = new ArrayList<>();
		cipherSuitesToTest = new ArrayList<>();
		protocolsToTest = new ArrayList<>();
		
		scansStarted = false;
		scansStoppedByUser = false;

		logDateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		
		listeners = new ArrayList<>();
		
		sslSocketFactory = null;
	}
	
	public void init(boolean certCollectingEnabled, boolean certAndHostnameVerificationEnabled) {
		this.certCollectingEnabled = certCollectingEnabled;
		this.certAndHostnameVerificationEnabled = certAndHostnameVerificationEnabled;
		sslSocketFactory = SSLUtil.getSSLSocketFactory(certAndHostnameVerificationEnabled);
	}
	
	public SSLSocketFactory getSSLSocketFactory() {
		return sslSocketFactory;
	}
	
	public boolean getCertCollectingEnabled() {
		return certCollectingEnabled;
	}
	
	public boolean getCertAndHostnameVerificationEnabled() {
		return certAndHostnameVerificationEnabled;
	}
	
	public void addListener(IScanTaskHandlerListener listener) {
		listeners.add(listener);
	}
	
	public void addScanTask(ScanTask scanTask) {
		scanTask.addListener(this);
		scanTask.setScanTaskHandler(this);
		scanTasks.add(scanTask);
	}
	
	public void setCipherSuitesForCollectingCert(List<String> cipherSuites) {
		cipherSuitesForCollectingCert.clear();
		for (String s : cipherSuites) {
			cipherSuitesForCollectingCert.add(s);
		}
	} 
	
	public String[] getCipherSuitsForCollectingCert() {
		String[] cipherSuites = new String[cipherSuitesForCollectingCert.size()];
		for (int i = 0; i < cipherSuitesForCollectingCert.size(); i++) {
			cipherSuites[i] = cipherSuitesForCollectingCert.get(i);
		}
		
		return cipherSuites;
	}
	
	public void setCipherSuitesToTest(List<String> cipherSuites) {
		cipherSuitesToTest.clear();
		for (String s : cipherSuites) {
			cipherSuitesToTest.add(s);
		}
	}
	public String getCipherSuiteToTest(int index) {
		return cipherSuitesToTest.get(index);
	}
	public int getCipherSuiteToTestIndex(String cipherSuite) {
		return cipherSuitesToTest.indexOf(cipherSuite);
	}
	public int getCipherSuitesToTestCount() {
		return cipherSuitesToTest.size();
	}

	
	public void setProtocolsToTest(List<String> protocols) {
		protocolsToTest.clear();
		for (String s : protocols) {
			protocolsToTest.add(s);
		}
	}
	public String getProtocolToTest(int index) {
		return protocolsToTest.get(index);
	}
	public int getProtocolToTestIndex(String protocol) {
		return protocolsToTest.indexOf(protocol);
	}
	public int getProtocolsToTestCount() {
		return protocolsToTest.size();
	}
	
	public List<ScanTask> getScanTasks() {
		return scanTasks;
	}
	
	public void startScans() {
		if (sslSocketFactory == null) {
			log(null, "InternalError: sslSocketFactory == null");
			return;
		}
		
		scansStarted = true;
		scansStoppedByUser = false;
		scanStartTime = System.currentTimeMillis();
		
		String hostString = (getScanTasksCount() == 1) ? "host" : "hosts";
		log(null, LOG_PREFIX + " Starting scan for " + scanTasks.size() + " " + hostString);				

		checkStartScans();
	}
	
	public void stopScans() {
		if (getScansFinished() == false) {
			for (ScanTask st : scanTasks) {
				st.stopThread();
			}
			
			log(null, LOG_PREFIX + " " + ScanTask.LOG_SCAN_STOPPED_BY_USER + Util.LF);
			scansStoppedByUser = true;
		}
	}
	
	public boolean getScansRunning() {
		if (scansStarted) {
			if (getScansFinished()) {
				return false;
			}
			else {
				return !scansStoppedByUser;
			}
		}
		else {
			return false;
		}
	}
	
	public int getScansFailedCount() {
		int counter = 0;
		for (ScanTask st : scanTasks) {
			if (st.getScanData().scanAborted && st.getScanData().scanStoppedByUser == false) {
				counter++;
			}
		}
		
		return counter;
	}
	
	public int getScansCompletedCount() {
		int counter = 0;
		for (ScanTask st : scanTasks) {
			if (st.getScanFinished() && st.getScanData().scanAborted == false) {
				counter++;
			}
		}
		
		return counter;
	}
	
	public int getScansRunningCount() {
		int runningScans = 0;
		for (ScanTask st : scanTasks) {
			if (st.getScanRunning()) {
				runningScans++;
			}
		}
		
		return runningScans;
	}
	
	public int getScanTasksCount() {
		return scanTasks.size();
	}
	
	public ScanTask.State getState() {
		if (scansStarted) {
			if (getScansFinished() && !scansStoppedByUser) {
				return State.DONE;
			}
			else if (scansStoppedByUser) {
				return State.STOPPED;
			}
			else {
				return State.RUNNING;
			}
		}
		else {
			return State.WAIT;
		}
	}
	
	private void checkStartScans() {
		int scansToStart = maxParallelScans - getScansRunningCount();
		if (scansToStart <= 0) {
			return;
		}
		
		for (ScanTask st : scanTasks) {
			if (scansToStart > 0 && st.getScanStarted() == false && st.getScanFinished() == false) {
				st.setScanTaskHandler(this);
				st.startThread();
				scansToStart--;
			}
		}
	}
	
	private boolean getScansFinished() {
		for (ScanTask st : scanTasks) {
			if (st.getScanFinished() == false) {
				return false;
			}
		}

		return true;
	}
	
	@Override
	public synchronized void onScanTaskStateChanged(ScanTask scanTask, String message) {
		if (scansStoppedByUser) {
			return;
		}
		
		if (message != null && message.equals("") == false) {
			float progress = 0;
			for (ScanTask st : scanTasks) {
				progress += st.getProgress();
			}
			
			progress = (progress / (scanTasks.size() * 100.0f)) * 100.0f;
			log(scanTask, getProgressString((int) progress) + message);
		}
		
		if (scanTask.getScanFinished() && scanTask.getScanData().scanStoppedByUser == false) {
			checkStartScans();	
		}
		
		if (getScansFinished()) {
			sendAllScanTasksFinishedMessageWithDelay(FINISH_MESSAGE_DELAY_TIME);
		}
	}
	
	private void sendAllScanTasksFinishedMessageWithDelay(int delayInMillis) {
		try {
			if (finishMessageDelayTimer != null) {
				finishMessageDelayTimer.cancel();
			}
			
			finishMessageDelayTimer = new Timer();
			finishMessageDelayTimer.schedule(new TimerTask() {
	            @Override
	            public void run() {
	            	sendAllScanTasksFinishedMessage();
	            }
	        }, delayInMillis);
		}
		catch (Exception e) {
		}
	}
	
	private void sendAllScanTasksFinishedMessage() {
		if (scansStoppedByUser == false) {
			String hostString = (getScanTasksCount() == 1) ? "host" : "hosts";
			float duration = (System.currentTimeMillis() - scanStartTime - FINISH_MESSAGE_DELAY_TIME) / 1000.0f;
			log(null, LOG_PREFIX + " Finished " + scanTasks.size() + " " + hostString + " in " + duration + " seconds " + Util.LF);
		}
		for (IScanTaskHandlerListener listener : listeners) {
			listener.onScanTaskHandlerDone();
		}
	}
	
	private String getProgressString(int progress) {
		if (progress < 10) {
			return "[" + (int) progress + "   %] ";
		}
		else if (progress < 100) {
			return "[" + (int) progress + "  %] ";
		}
		
		return "[" + (int) progress + " %] ";
	}
	
	private void log(ScanTask scanTask, String message) {
		if (message != null && message != "") {
			for (IScanTaskHandlerListener listener : listeners) {
				String date = logDateFormat.format(new Date());
				String m = "[" + date + "] " + message;
				listener.onScanTaskHandlerMessage(scanTask, m);
			}
		}
	}
}
