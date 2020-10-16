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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.bitbatzen.tlsserverscanner.Util;


public class SSLUtil {
	
	private static final HashMap<String, String> certExtensionsMap = createCertExtensionsMap();
	
    private static HostnameVerifier DEFAULT_HOSTNAME_VERIFIER = HttpsURLConnection.getDefaultHostnameVerifier();
    private static SSLSocketFactory DEFAULT_SSL_SOCKET_FACTORY = HttpsURLConnection.getDefaultSSLSocketFactory();
	
    private static final TrustManager[] ALL_TRUSTING_TRUST_MANAGER = new TrustManager[] {
        new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {}
            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        }
    };

    private static final HostnameVerifier ALL_TRUSTING_HOSTNAME_VERIFIER = new HostnameVerifier() {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };
    
    public static SSLSocketFactory getSSLSocketFactory(boolean certAndHostnameVerificationEnabled) {
    	HostnameVerifier hostnameVerifier = DEFAULT_HOSTNAME_VERIFIER;
    	SSLSocketFactory sslSocketFactory = DEFAULT_SSL_SOCKET_FACTORY;

    	if (certAndHostnameVerificationEnabled == false) {
	    	try {
	            SSLContext sc = SSLContext.getInstance("TLS");
	            sc.init(null, ALL_TRUSTING_TRUST_MANAGER, new java.security.SecureRandom());
	            sslSocketFactory = sc.getSocketFactory();
	    	}
	    	catch (Exception e) {
	    		e.printStackTrace();
	    	}
	    	
	    	hostnameVerifier = ALL_TRUSTING_HOSTNAME_VERIFIER;
    	}
    	
		HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier);
		HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);
		
		return HttpsURLConnection.getDefaultSSLSocketFactory();
    }
    
    public static List<String> getAvailableCipherSuites() {
    	String[] cipherSuites = HttpsURLConnection.getDefaultSSLSocketFactory().getDefaultCipherSuites();
    	List<String> list = new ArrayList<>();
    	for (String s : cipherSuites) {
    		list.add(s);
    	 }
    	
    	return list;		
    }
    
	public static List<String> getAvailableProtocols() {
		List<String> list = new ArrayList<>();
		SSLSocket socket = null;
		
		try {
			socket = (SSLSocket) getSSLSocketFactory(false).createSocket();
			String[] protocols = socket.getSupportedProtocols();
			for (String s : protocols) {
				if (s.equals("SSLv2Hello") == false) {
					list.add(s);
				}
			}
			return list;
		}
		catch (IOException e) {
			return list;
		}
		finally {
			Util.close(socket);
		}
	}
	
	public static String getCertExtensionName(String oid) {
		String name = certExtensionsMap.get(oid);
		return (name == null) ? "Unkown" : name; 
	}
	
	private static HashMap<String, String> createCertExtensionsMap() {
		HashMap<String, String> map = new HashMap<>();
//		map.put("1.3.6.1.4.1.11129.2.4.2", "");
		map.put("1.3.6.1.5.5.7.1.1", "Authority Info Access");
		
		map.put("2.5.29.1", "old Authority Key Identifier");
		map.put("2.5.29.2", "old Primary Key Attributes ");
		map.put("2.5.29.3", "Certificate Policies");
		map.put("2.5.29.4", "Primary Key Usage Restriction");
		map.put("2.5.29.9", "Subject Directory Attributes");
		
		map.put("2.5.29.14", "Subject Key Identifier");
		map.put("2.5.29.15", "Key Usage");
		map.put("2.5.29.16", "Private Key Usage Period");
		map.put("2.5.29.17", "Subject Alternative Name");
		map.put("2.5.29.18", "Issuer Alternative Name");
		
		map.put("2.5.29.19", "Basic Constraints");
		map.put("2.5.29.20", "CRL Number");
		map.put("2.5.29.21", "Reason code");
		map.put("2.5.29.23", "Hold Instruction Code");
		map.put("2.5.29.24", "Invalidity Date");
		
		map.put("2.5.29.27", "Delta CRL indicator");
		map.put("2.5.29.28", "Issuing Distribution Point");
		map.put("2.5.29.29", "Certificate Issuer");
		map.put("2.5.29.30", "Name Constraints");
		map.put("2.5.29.31", "CRL Distribution Points");
		
		map.put("2.5.29.32", "Certificate Policies");
		map.put("2.5.29.33", "Policy Mappings");
		map.put("2.5.29.35", "Authority Key Identifier");
		map.put("2.5.29.36", "Policy Constraints");
		map.put("2.5.29.37", "Extended key usage");
		
		map.put("2.5.29.46", "FreshestCRL");
		map.put("2.5.29.54", "X.509 version 3 certificate extension Inhibit Any-policy");
		return map;
	}
}
