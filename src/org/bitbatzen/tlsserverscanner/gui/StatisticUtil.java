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

import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.bitbatzen.tlsserverscanner.Util;
import org.bitbatzen.tlsserverscanner.scantask.Cert;
import org.bitbatzen.tlsserverscanner.scantask.SSLUtil;
import org.bitbatzen.tlsserverscanner.scantask.ScanTask;
import org.bitbatzen.tlsserverscanner.scantask.ScanTaskHandler;


public class StatisticUtil {

	
	private static <K, V extends Comparable<V>> Map<K, V> sortByValues(final Map<K, V> map) {
	    Comparator<K> valueComparator =  new Comparator<K>() {
	        public int compare(K k1, K k2) {
	            int compare = map.get(k2).compareTo(map.get(k1));
	            if (compare == 0) return 1;
	            else return compare;
	        }
	    };
	    
	    Map<K, V> sortedByValues = new TreeMap<K, V>(valueComparator);
	    sortedByValues.putAll(map);
	    return sortedByValues;
	}
	
	private static HashMap<Integer, Integer> createEmptyStatisicMap(int size) {
		HashMap<Integer, Integer> statisticMap = new HashMap<>();
		for (int i = 0; i < size; i++) {
			statisticMap.put(i, 0);
		}		
		
		return statisticMap;
	}
	
	private static String getAmountString(float max, float v) {
		if (v > 0) {
			String percentage = String.format("%.2f", (float) v / (float) max * 100.0f);
			return "<b> (" + (int) v + ", " + percentage + "%)</b>";
		}
		else {
			return "<b> (" + (int) v + ")</b>";
		}
	}
	
	public static void appendCipherSuiteChosenFromServerStatistic(StringBuilder sb, ScanTaskHandler scanTaskHandler) {
		HashMap<String, Integer> statisticMap = new HashMap<>();
		
		for (ScanTask st : scanTaskHandler.getScanTasks()) {
			if (st.getScanData().getCertAvailable() == false) {
				continue;
			}
			
			String sscCipherSuite = st.getScanData().cipherSuiteChosenByServer;
			if (sscCipherSuite.isEmpty() == false) {
				if (statisticMap.containsKey(sscCipherSuite)) {
					int v = statisticMap.get(sscCipherSuite) + 1;
					statisticMap.put(sscCipherSuite, v);					
				}
				else {
					statisticMap.put(sscCipherSuite, 1);
				}
			}
		}
		
		Map<String, Integer> sortedMap = sortByValues(statisticMap);
		for (Map.Entry<String, Integer> entry : sortedMap.entrySet()) {
			sb.append(entry.getKey() + " " + getAmountString(scanTaskHandler.getScanTasks().size(), entry.getValue()) + Util.BR);
		}
	}
	
	
	public static void appendProtocolStatistic(StringBuilder sb, ScanTaskHandler scanTaskHandler) {
		HashMap<Integer, Integer> statisticMap = createEmptyStatisicMap(scanTaskHandler.getProtocolsToTestCount());
		
		for (ScanTask st : scanTaskHandler.getScanTasks()) {
			HashMap<Integer, Boolean> tested = st.getScanData().protocolsTested;
			for (Map.Entry<Integer, Boolean> entry : tested.entrySet()) {
			    if (entry.getValue() == true) {
		    		statisticMap.put(entry.getKey(), statisticMap.get(entry.getKey()) + 1);
			    }
			}
		}
		
		Map<Integer, Integer> sortedMap = sortByValues(statisticMap);
		for (Map.Entry<Integer, Integer> entry : sortedMap.entrySet()) {
			String protocol = scanTaskHandler.getProtocolToTest(entry.getKey());
			sb.append(protocol + getAmountString(scanTaskHandler.getScanTasks().size(), entry.getValue()) + Util.BR);
		}
	}
	
	public static void appendCipherSuiteStatistic(StringBuilder sb, ScanTaskHandler scanTaskHandler) {
		HashMap<Integer, Integer> statisticMap = createEmptyStatisicMap(scanTaskHandler.getCipherSuitesToTestCount());
		
		for (ScanTask st : scanTaskHandler.getScanTasks()) {
			HashMap<Integer, Boolean> tested = st.getScanData().cipherSuitesTested;
			for (Map.Entry<Integer, Boolean> entry : tested.entrySet()) {
			    if (entry.getValue() == true) {
		    		statisticMap.put(entry.getKey(), statisticMap.get(entry.getKey()) + 1);
			    }
			}
		}
		
		Map<Integer, Integer> sortedMap = sortByValues(statisticMap);
		for (Map.Entry<Integer, Integer> entry : sortedMap.entrySet()) {
			String cipherSuite = scanTaskHandler.getCipherSuiteToTest(entry.getKey());
			sb.append(cipherSuite + getAmountString(scanTaskHandler.getScanTasks().size(), entry.getValue()) + Util.BR);
		}
	}
	
	public static void appendCertificatePubKeyAlgorithmStatistic(StringBuilder sb, ScanTaskHandler scanTaskHandler) {
		HashMap<String, Integer> statisticMap = new HashMap<>();
		
		for (ScanTask st : scanTaskHandler.getScanTasks()) {
			if (st.getScanData().getCertAvailable() == false) {
				continue;
			}
			
			String pubKeyAlgorithm = st.getScanData().certs[0].getPublicKeyAlgorithm();
			if (pubKeyAlgorithm.isEmpty() == false) {
				if (statisticMap.containsKey(pubKeyAlgorithm)) {
					int v = statisticMap.get(pubKeyAlgorithm) + 1;
					statisticMap.put(pubKeyAlgorithm, v);					
				}
				else {
					statisticMap.put(pubKeyAlgorithm, 1);
				}
			}
		}
		
		Map<String, Integer> sortedMap = sortByValues(statisticMap);
		for (Map.Entry<String, Integer> entry : sortedMap.entrySet()) {
			sb.append(entry.getKey() + " " + getAmountString(scanTaskHandler.getScanTasks().size(), entry.getValue()) + Util.BR);
		}
	}
	
	public static void appendCertificatePubKeyAlgorithmWithKeyLengthStatistic(StringBuilder sb, ScanTaskHandler scanTaskHandler) {
		HashMap<String, Integer> statisticMap = new HashMap<>();
		
		for (ScanTask st : scanTaskHandler.getScanTasks()) {
			if (st.getScanData().getCertAvailable() == false) {
				continue;
			}
			
			String pubKeyAlgorithm = st.getScanData().certs[0].getPublicKeyAlgorithm();
			if (pubKeyAlgorithm.isEmpty()) {
				continue;
			}
			
			pubKeyAlgorithm = st.getScanData().certs[0].getPublicKeyAlgorithmWithKeyLength();
			if (statisticMap.containsKey(pubKeyAlgorithm)) {
				int v = statisticMap.get(pubKeyAlgorithm) + 1;
				statisticMap.put(pubKeyAlgorithm, v);					
			}
			else {
				statisticMap.put(pubKeyAlgorithm, 1);
			}
		}
		
		Map<String, Integer> sortedMap = sortByValues(statisticMap);
		for (Map.Entry<String, Integer> entry : sortedMap.entrySet()) {
			sb.append(entry.getKey() + " " + getAmountString(scanTaskHandler.getScanTasks().size(), entry.getValue()) + Util.BR);
		}
	}
	
	public static void appendCertificateSignatureAlgorithmStatistic(StringBuilder sb, ScanTaskHandler scanTaskHandler) {
		HashMap<String, Integer> statisticMap = new HashMap<>();
		
		for (ScanTask st : scanTaskHandler.getScanTasks()) {
			if (st.getScanData().getCertAvailable() == false) {
				continue;
			}
			
			String signatureAlgorithm = st.getScanData().certs[0].getSignatureAlgorithm();
			if (signatureAlgorithm.isEmpty() == false) {
				if (statisticMap.containsKey(signatureAlgorithm)) {
					int v = statisticMap.get(signatureAlgorithm) + 1;
					statisticMap.put(signatureAlgorithm, v);					
				}
				else {
					statisticMap.put(signatureAlgorithm, 1);
				}
			}
		}
		
		Map<String, Integer> sortedMap = sortByValues(statisticMap);
		for (Map.Entry<String, Integer> entry : sortedMap.entrySet()) {
			sb.append(entry.getKey() + " " + getAmountString(scanTaskHandler.getScanTasks().size(), entry.getValue()) + Util.BR);
		}
	}
	
	public static void appendCertificateExtensionStatistic(StringBuilder sb, ScanTaskHandler scanTaskHandler) {
		HashMap<String, Integer> statisticMap = new HashMap<>();
		
		for (ScanTask st : scanTaskHandler.getScanTasks()) {
			if (st.getScanData().getCertAvailable() == false) {
				continue;
			}
			
			List<String> extensions = st.getScanData().certs[0].getExtensionOIDs();
			for (String s : extensions) {
				if (statisticMap.containsKey(s)) {
					int v = statisticMap.get(s) + 1;
					statisticMap.put(s, v);					
				}
				else {
					statisticMap.put(s, 1);
				}
			}
		}
		
		Map<String, Integer> sortedMap = sortByValues(statisticMap);
		for (Map.Entry<String, Integer> entry : sortedMap.entrySet()) {
			String extension = "(" + entry.getKey() + ") " + SSLUtil.getCertExtensionName(entry.getKey());
			sb.append(extension + getAmountString(scanTaskHandler.getScanTasks().size(), entry.getValue()) + Util.BR);
		}
	}
	
	public static void appendCertificateRootCAOrganisationStatistic(StringBuilder sb, ScanTaskHandler scanTaskHandler) {
		HashMap<String, Integer> statisticMap = new HashMap<>();
		
		for (ScanTask st : scanTaskHandler.getScanTasks()) {
			if (st.getScanData().getCertAvailable() == false) {
				continue;
			}
			
			String rootCAOrg = Cert.getNameValue(st.getScanData().getCertRootName(), "O=");
			if (rootCAOrg.isEmpty() == false) {
				if (statisticMap.containsKey(rootCAOrg)) {
					int v = statisticMap.get(rootCAOrg) + 1;
					statisticMap.put(rootCAOrg, v);					
				}
				else {
					statisticMap.put(rootCAOrg, 1);
				}
			}
		}
		
		Map<String, Integer> sortedMap = sortByValues(statisticMap);
		for (Map.Entry<String, Integer> entry : sortedMap.entrySet()) {
			sb.append(entry.getKey() + getAmountString(scanTaskHandler.getScanTasks().size(), entry.getValue()) + Util.BR);
		}
	}
}
