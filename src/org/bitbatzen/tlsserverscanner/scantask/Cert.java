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

import java.security.cert.X509Certificate;
import java.math.BigInteger;
import java.security.cert.CertificateParsingException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.crypto.interfaces.DHPublicKey;

import org.bitbatzen.tlsserverscanner.Util;


public class Cert {

	private X509Certificate cert;
	
	
	public Cert(X509Certificate cert) {
		this.cert = cert;
	}
	
	public X509Certificate getCert() {
		return cert;
	}
	
	public String getSubjectName() {
		return cert.getSubjectX500Principal().getName();
	}
	
	public String getIssuerName() {
		return cert.getIssuerX500Principal().getName(); 
	}
	
	public static String getNameValue(String certName, String searchTag) {
		if (certName == null || certName.isEmpty()) {
			return "";
		}
		
		int begin = certName.indexOf(searchTag);
		int end = certName.indexOf(",", begin);
		if (end < begin) {
			end = certName.length();
		}
		
		while (certName.charAt(end - 1) == '\\') {
			end = certName.indexOf(",", end + 1);
		}
		
		if (begin != -1 && end != -1) {
			String subString = certName.substring(begin + searchTag.length(), end);
			return subString.replace("\\", "");
		}
		else {
			return "";
		}		
	}
	
	public static String formatCertName(String s) {
		if (s == null) {
			return "";
		}
		
		s = s.replace("\\", "");
		return s.replace(",", ", ");
	}
	
	public static String formatCertName2(String s) {
		if (s == null) {
			return "";
		}
	
		s = s.replace("\\,", "@@@");
		String formatted = "";
		String[] splitted = s.split(",");
		for (String ss : splitted) {
			formatted += ss.replace("=", " = ") + Util.BR;				
		}
		
		return formatted.replace("@@@", ",");
	}
	
	public String[] getSubjectAlternativeNames() {
		try {
			Collection<List<?>> col = cert.getSubjectAlternativeNames();
			if (col == null) {
				return null;
			}
			String[] alts = new String[col.size()];
			int c = 0;
		    for (List<?> l : col) {
	    		alts[c] = l.get(1).toString();
		    	c++;
		    }
		    return alts;
		}
		catch (CertificateParsingException e) {
			return null;
		}
	}
	
	public String getVersion() {
		return Integer.toString(cert.getVersion());
	}
	
	public String getType() {
		return cert.getType();
	}
	
	public BigInteger getSerialNumber() {
		return cert.getSerialNumber();	
	}
	
	public Date getNotBefore() {
		return cert.getNotBefore();
	}
	
	public Date getNotAfter() {
		return cert.getNotAfter();
	}
	
	public String getSignatureAlgorithm() {
		return cert.getSigAlgName();			
	}
	
	public String getPublicKeyAlgorithm() {
		return cert.getPublicKey().getAlgorithm();
	}
	
	public String getPublicKeyLength() {
		if (cert.getPublicKey() instanceof RSAPublicKey) {
			RSAPublicKey rsaPubKey = (RSAPublicKey) cert.getPublicKey();
			return Integer.toString(rsaPubKey.getModulus().bitLength()); 
		}
		else if (cert.getPublicKey() instanceof ECPublicKey) {
			ECPublicKey ecPubKey = (ECPublicKey) cert.getPublicKey();
			return Integer.toString(ecPubKey.getParams().getCurve().getField().getFieldSize());
		}
		else if (cert.getPublicKey() instanceof DHPublicKey) {
			DHPublicKey dhPubKey = (DHPublicKey) cert.getPublicKey();
			return Integer.toString(dhPubKey.getParams().getP().bitLength());
		}
		else if (cert.getPublicKey() instanceof DSAPublicKey) {
			DSAPublicKey dsaPubKey = (DSAPublicKey) cert.getPublicKey();
			return Integer.toString(dsaPubKey.getParams().getP().bitLength());
		}
		else {
			return "Unkown";
		}
	}
	
	public String getPublicKeyAlgorithmWithKeyLength() {
		return getPublicKeyAlgorithm() + " (" + getPublicKeyLength() + ")";
	}
	
	public List<String> getExtensionOIDs() {
		List<String> oids = new ArrayList<>();
		
		Set<String> criticalExtensions = cert.getCriticalExtensionOIDs();
		if (criticalExtensions != null && criticalExtensions.isEmpty() == false) {
			oids.addAll(criticalExtensions);
		}
		
		Set<String> nonCriticalExtensions = cert.getNonCriticalExtensionOIDs();
		if (nonCriticalExtensions != null && nonCriticalExtensions.isEmpty() == false) {
			oids.addAll(nonCriticalExtensions);
		}		
		
		return oids;
	}
	
	public List<String> getExtensionOIDsWithName() {
		List<String> oidsWithName = new ArrayList<>();
		List<String> oids = getExtensionOIDs();
		for (String oid : oids) {
			oidsWithName.add("(" + oid + ") " + SSLUtil.getCertExtensionName(oid));
		}
		
		return oidsWithName;
	}
}
