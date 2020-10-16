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

import java.net.InetAddress;
import java.util.HashMap;


public class ScanData {
	
	public String host;
	public int port;
	
	public InetAddress inetAddr;
	
	public boolean scanStarted;
	public boolean scanFinished;
	
	public boolean scanAborted;
	public boolean scanStoppedByUser;
	
	public enum ScanError {
		NONE,
		FAILED_TO_RESOLVE_HOSTNAME,
		PORT_NOT_REACHABLE,
		FAILED_TO_CREATE_SOCKET,
		INVALID_SSL_PARAMETER,
		SSL_HANDSHAKE_TIMEOUT,
		MAYBE_NO_SSL_SERVICE_RUNNING,
		INVALID_CERTIFICATE,
		FAILED_TO_FETCH_CERTIFICATE
	}
	
	public ScanError scanError;
	
	public HashMap<Integer, Boolean> cipherSuitesTested;
	public HashMap<Integer, Boolean> protocolsTested;
	
	public Cert[] certs;
	
	public String cipherSuiteChosenByServer;
	
	
	public ScanData(String host, int port) {
		this.host = host;
		this.port = port;
		inetAddr = null;
		
		scanStarted = false;
		scanFinished = false;
		
		scanAborted = false;
		scanStoppedByUser = false;
		
		scanError = ScanError.NONE;
		
		cipherSuitesTested = new HashMap<>();
		protocolsTested = new HashMap<>();
		
		certs = null;
		cipherSuiteChosenByServer = "";
	}
	
	public static String getErrorInfo(ScanError scanError) {
		switch (scanError) {
		case FAILED_TO_RESOLVE_HOSTNAME:
			return "Failed to resolve hostname!";
		case PORT_NOT_REACHABLE:
			return "Port not reachable!";
		case FAILED_TO_CREATE_SOCKET:
			return "Failed to create ssl socket!";
		case INVALID_SSL_PARAMETER:
			return "Invalid ssl parameter!";
		case SSL_HANDSHAKE_TIMEOUT:
			return "Timeout during ssl handshake!";
		case MAYBE_NO_SSL_SERVICE_RUNNING:
			return "No ssl service running?";
		case INVALID_CERTIFICATE: 
			return "Invalid certificate!";
		case FAILED_TO_FETCH_CERTIFICATE:
			return "Failed to fetch certificate! (Cipher suites not supported?)";
		default:
			return "";
		}		
	}
	
	public String getErrorInfo() {
		return getErrorInfo(scanError);
	}
	
	public boolean isHostnameResolved() {
		return (inetAddr != null && inetAddr.getHostAddress() != null && inetAddr.getHostAddress() != "");
	}
	
	public String getHostAddress() {
		if (isHostnameResolved()) {
			return inetAddr.getHostAddress();
		}
		else {
			return "";
		}
	}
	
	public String getHostWithPort() {
		return host + ":" + port;
	}
	
	public boolean getCertAvailable() {
		return certs != null && certs.length > 0 && certs[0] != null;
	}
	
	public String getCertSubjectName() {
		return certs[0].getSubjectName();
	}
	
	public String[] getCertNames() {
		String[] certNames = new String[certs.length];
		for (int i = 0; i < certs.length; i++) {
			Cert c = certs[i];
			String name = "";
			name = Cert.getNameValue(c.getSubjectName(), "CN=");
			if (name.equals("")) {
				name = "Issuer (" + i + ")";
			}
				
			certNames[i] = name;
		}
		
		return certNames;
	}
	
	public String getCertRootName() {
		return certs[certs.length - 1].getIssuerName();
	}
	
	public boolean getIsCertSelfSigned() {
		return getCertSubjectName().equals(getCertRootName());
	}
}
