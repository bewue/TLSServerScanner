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

import java.awt.Color;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.bitbatzen.tlsserverscanner.Util;
import org.bitbatzen.tlsserverscanner.scantask.ScanData.ScanError;


public class ScanTask implements Runnable {
	
	public static final String LOG_SCAN_STOPPED_BY_USER = "Scan was stopped by user!";
	
	public enum State {
		NONE,
		WAIT,
		RUNNING,
		ERROR,
		STOPPED,
		DONE
	}
	
	private ScanTaskHandler scanTaskHandler;

	private static final int PORT_REACHABLE_CHECK_TIMEOUT = 8000;

	private static final int SSL_HANDSHAKE_TIMEOUT = 8000;
	private Timer timeoutTimer;
	
	private float progress;
	
	private Thread thread;
	
	private List<IScanTaskListener> listeners;
	
	private ScanData sd;
	
	private static final String ERROR_LOG_TAG = "Error:";
	
	private SSLParameters sslParams;
	
	
	public ScanTask(String host, int port) {
		sd = new ScanData(host, port);
		
		scanTaskHandler = null;

		progress = 0.0f;
		
        timeoutTimer = null;
        
        listeners = new ArrayList<>();
        
        sslParams = new SSLParameters();
	}
	
	public void addListener(IScanTaskListener listener) {
		listeners.add(listener);
	}
	
	public void startThread() {
		sd.scanStarted = true;
		sd.scanFinished = false;
		progress = 0.0f;
		
		thread = new Thread(this);
		thread.start();		
	}
	
	public void stopThread() {
		if (sd.scanFinished == false) {
			sd.scanStoppedByUser = true;
			if (sd.scanStarted) {
				sd.scanAborted = true;
				finish(LOG_SCAN_STOPPED_BY_USER);		
			}
			else {
				stateChanged(null);	
			}
		}
		else {
			stateChanged(null);
		}
	}
	
	public boolean getScanFinished() {
		return sd.scanFinished;
	}
	
	public boolean getScanStarted() {
		return sd.scanStarted;
	}

	public ScanData getScanData() {
		return sd;
	}
	
	public float getProgress() {
		return progress;
	}
	
	public boolean getScanRunning() {
		return sd.scanStarted && !sd.scanFinished;
	}
	
	public void setScanTaskHandler(ScanTaskHandler scanTaskHandler) {
		this.scanTaskHandler = scanTaskHandler;
	}
	
	public ScanTaskHandler getScanTaskHandler() {
		return scanTaskHandler;
	}
	
	private void abortScan(ScanError scanError) {
		if (sd.scanAborted) {
			return;
		}
		
		sd.scanAborted = true;
		sd.scanError = scanError;
		finish(ERROR_LOG_TAG + " " + ScanData.getErrorInfo(scanError));		
	}
	
	@Override public void run() {
		stateChanged("Starting Host Check");
		sd.inetAddr = resolveHost(sd.host);
		if (sd.isHostnameResolved() == false) {
			abortScan(ScanError.FAILED_TO_RESOLVE_HOSTNAME);
			return;
		}
		if (sd.host.equals(sd.inetAddr.getHostAddress()) == false) {
			progress += 5.0f;
			stateChanged("Resolved Hostname > " + sd.inetAddr.getHostAddress());
		}
		if (sd.scanAborted) {
			return; 
		}
		
		if (isPortReachable(sd.inetAddr.getHostAddress(), sd.port) == false) {
			abortScan(ScanError.PORT_NOT_REACHABLE);
			return;
		}
		progress += 5.0f;
		
		int protocolsToTestCount = scanTaskHandler.getProtocolsToTestCount(); 
		int cipherSuitesToTestCount = scanTaskHandler.getCipherSuitesToTestCount();
		
		if (protocolsToTestCount == 0 && cipherSuitesToTestCount == 0) {
			stateChanged("Port Reachable");			
		}
		else {
			stateChanged("Port Reachable, Starting Scan...");
		}
		
		// certificate collecting
		if (scanTaskHandler.getCertCollectingEnabled()) {
			startTimeoutTimer();
			testFetchCertificate(sd.inetAddr.getHostAddress(), sd.port, scanTaskHandler.getCipherSuitsForCollectingCert());
			if (sd.scanAborted) {
				return;
			}
		}

		float increment = (100.0f - progress) / (protocolsToTestCount + cipherSuitesToTestCount);
		
		// protocol tests
		if (protocolsToTestCount > 0) {
			for (int i = 0; i < protocolsToTestCount; i++) {
				startTimeoutTimer();
				testProtocol(sd.inetAddr.getHostAddress(), sd.port, i);
				if (sd.scanAborted) {
					return;
				}
				progress += increment;
			}
		}
		
		// cipher suite tests
		if (cipherSuitesToTestCount > 0) {
			for (int i = 0; i < cipherSuitesToTestCount; i++) {
				startTimeoutTimer();
				testCipherSuite(sd.inetAddr.getHostAddress(), sd.port, i);
				if (sd.scanAborted) {
					return;
				}
				progress += increment;
			}
		}
		
		finish("Finished");
	}
	
	private void onSSLHandshakeTimeout() {
		abortScan(ScanError.SSL_HANDSHAKE_TIMEOUT);
	}
	
	private void finish(String logMessage) {
		cancelTimeoutTimer();
		progress = 100.0f;
		sd.scanFinished = true;

		stateChanged(logMessage);
	}
	
	private void startTimeoutTimer() {
		try {
			if (timeoutTimer != null) {
				timeoutTimer.cancel();
			}
			
			timeoutTimer = new Timer();
	        timeoutTimer.schedule(new TimerTask() {
	            @Override
	            public void run() {
	            	onSSLHandshakeTimeout();
	            }
	        }, SSL_HANDSHAKE_TIMEOUT);
		}
		catch (Exception e) {
		}
	}
	
	private void cancelTimeoutTimer() {
		if (timeoutTimer == null) {
			return;
		}
		
		try {
			timeoutTimer.cancel();
		}
		catch (Exception e) {
		}
	}
	
	private void setDefault(SSLParameters sslParams) {
		sslParams.setAlgorithmConstraints(null);
		sslParams.setCipherSuites(null);
		sslParams.setEndpointIdentificationAlgorithm(null);
		sslParams.setNeedClientAuth(false);
		sslParams.setWantClientAuth(false);
	}
	
	private SSLSession trySSLHandshake(String hostIP, int port, SSLParameters sslParams) throws SSLHandshakeException {
		SSLSocket socket = null;
		try {
			socket = (SSLSocket) scanTaskHandler.getSSLSocketFactory().createSocket(hostIP, port);
		}
		catch (Exception e) {
			abortScan(ScanError.FAILED_TO_CREATE_SOCKET);
			Util.close(socket);
			return null;
		}
		
		try {
			socket.setSSLParameters(sslParams);
		}
		catch (IllegalArgumentException iae) {
			abortScan(ScanError.INVALID_SSL_PARAMETER);
			return null;
		}
		
		try {
			socket.startHandshake();
			SSLSession sslSession = socket.getSession();
			return sslSession;
		}
		catch (SSLHandshakeException sslhe) {
			if (sslhe.getMessage().contains("ValidatorException")) {
				abortScan(ScanError.INVALID_CERTIFICATE);
			}
			
			throw sslhe;				
		}
		catch (Exception e) {
			abortScan(ScanError.MAYBE_NO_SSL_SERVICE_RUNNING);
			return null;
		}
		finally {
			Util.close(socket);		
		}	
	}
	
	private boolean isSSLSessionValid(SSLSession sslSession) {
		return !sd.scanAborted && sslSession != null 
				&& sslSession.getCipherSuite().equals("SSL_NULL_WITH_NULL_NULL") == false;
	}

	private void testFetchCertificate(String hostIP, int port, String[] availableCipherSuites) {
		setDefault(sslParams);
		
		if (availableCipherSuites != null && availableCipherSuites.length > 0) {
			sslParams.setCipherSuites(availableCipherSuites);
		}
    
		try {
			SSLSession sslSession = trySSLHandshake(hostIP, port, sslParams);
			
			if (isSSLSessionValid(sslSession)) {
				if (sd.getCertAvailable() == false) {
					sd.certs = getCerts(sslSession);
					sd.cipherSuiteChosenByServer = sslSession.getCipherSuite();
					stateChanged("Fetched Certificates");
				}
			}
		}
		catch (SSLHandshakeException sslhe) {
			abortScan(ScanError.FAILED_TO_FETCH_CERTIFICATE);				
		}
	}
	
	private void testProtocol(String hostIP, int port, int protocolIndex) {
		setDefault(sslParams);
		
		String protocol = scanTaskHandler.getProtocolToTest(protocolIndex);
		sslParams.setProtocols(new String[] {protocol} );
	    
		try {
			SSLSession sslSession = trySSLHandshake(hostIP, port, sslParams);
			
			if (isSSLSessionValid(sslSession)) {
				int index = scanTaskHandler.getProtocolToTestIndex(sslSession.getProtocol());
				sd.protocolsTested.put(index, true);
				stateChanged(sslSession.getProtocol() + " > SUPPORTED");
			}
		}
		catch (SSLHandshakeException sslhe) {
			int index = scanTaskHandler.getProtocolToTestIndex(protocol);
			sd.protocolsTested.put(index, false);
			stateChanged(null);
		}
	}

	private void testCipherSuite(String hostIP, int port, int cipherSuiteIndex) {
		setDefault(sslParams);
		
		String cipherSuite = scanTaskHandler.getCipherSuiteToTest(cipherSuiteIndex);
		sslParams.setCipherSuites(new String[] {cipherSuite} );
    
		try {
			SSLSession sslSession = trySSLHandshake(hostIP, port, sslParams);
			
			if (isSSLSessionValid(sslSession)) {
				int index = scanTaskHandler.getCipherSuiteToTestIndex(sslSession.getCipherSuite());
				sd.cipherSuitesTested.put(index, true);
				stateChanged(sslSession.getCipherSuite() + " > SUPPORTED");
			}
		}
		catch (SSLHandshakeException sslhe) {
			if (sslhe.getMessage().contains("ValidatorException") == false) {
				sd.cipherSuitesTested.put(cipherSuiteIndex, false);
				stateChanged(null);
			}
		}
	}
	
	private void stateChanged(String message) {
		for (IScanTaskListener listener : listeners) {
			String m = null;
			if (message != null && message.equals("") == false) {
				m = "[" + sd.host + ":" + sd.port + "] [" + message + "]";
			}
			listener.onScanTaskStateChanged(this, m);
		}
	}
	
	private InetAddress resolveHost(String host) {
		try {
			InetAddress inetAddr = InetAddress.getByName(host);
			return inetAddr;
		}
	    catch (UnknownHostException uhe) {
	    	return null;
	    }
	}
	
	private boolean isPortReachable(String host, int port) {
	    Socket socket = null;
	    try {
	        socket = new Socket();
	        socket.connect(new InetSocketAddress(host, port), PORT_REACHABLE_CHECK_TIMEOUT);
	        return true;
	    }
	    catch (Exception e) {
	    	return false;
	    } 
	    finally {
	    	Util.close(socket);
	    }
	}
	
	private Cert[] getCerts(SSLSession sslSession) {
		java.security.cert.Certificate[] servercerts;
		try {
		    servercerts = sslSession.getPeerCertificates();
		}
		catch (SSLPeerUnverifiedException e) {
			return null;
		}
		
		if (servercerts[0] instanceof java.security.cert.X509Certificate) {
			Cert[] certs = new Cert[servercerts.length];
			for (int i = 0; i < servercerts.length; i++) {
				certs[i] = new Cert((java.security.cert.X509Certificate) servercerts[i]);
			}
			
			return certs;
		}
		else {
			return null;
		}
	}
	
	public static State getState(ScanTask scanTask) {
		if (scanTask == null) {
			return State.NONE;
		}
		
		if (scanTask.getScanStarted() == false) {
			if (scanTask.getScanData().scanStoppedByUser) {
				return State.STOPPED;
			}
			else {
				return State.WAIT;
			}
		}
		else {
			if (scanTask.getScanFinished()) {
				if (scanTask.getScanData().scanAborted) {
					if (scanTask.getScanData().scanStoppedByUser) {
						return State.STOPPED;
					}
					else {
						return State.ERROR;	
					}
				}
				else {
					return State.DONE;
				}
			}
			else {
				return State.RUNNING;
			}
		}
	}
	
	public static Color getStateColor(State state) {
		switch (state) {
		case NONE:
		case WAIT:
			return Color.WHITE;
		case STOPPED:
			return Color.LIGHT_GRAY;
		case RUNNING: 
			return new Color(255, 255, 20);
		case ERROR:
			return new Color(230, 0, 0);
		case DONE:
			return new Color(50, 200, 50);
		default:
			return Color.WHITE;
		}
	}
	
	public static String getStateTag(State state) {
		switch (state) {
		case NONE:
		case WAIT:
			return "[WAIT]";
		case RUNNING: 
			return"[RUNNING]";
		case ERROR:
			return "[ERROR]";
		case DONE:
			return "[DONE]";
		case STOPPED:
			return "[STOPPED]";
		default:
			return "[WAIT]";
		}
	}
}
