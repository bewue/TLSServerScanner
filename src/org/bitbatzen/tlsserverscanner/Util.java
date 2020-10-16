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

package org.bitbatzen.tlsserverscanner;

import java.awt.Color;
import java.awt.Font;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.bitbatzen.tlsserverscanner.gui.HostListItem;
import org.bitbatzen.tlsserverscanner.scantask.Cert;


public class Util {
	
	public static final String T_APP_NAME = "TLSServerScanner";
	public static final String T_APP_VERSION = "1.0.1";
	public static final String T_APP_LICENSE = "GPLv3";
	public static final String T_AUTOR = "Benjamin W.";
	public static final String T_CONTACT_EMAIL = "bitbatzen@gmail.com";
	public static final String T_CODE_URL = "https://github.com/bewue/tlsserverscanner";
	
	public static final String LF = System.lineSeparator();
	public static final String BR = "<br>";
	
	public static final String COLOR_END_TAG = "</font>";
	public static final String FONT_END_TAG = "</font>";
	
	
	public static String getJavaVersionString() {
		return System.getProperty("java.version");
	}
	
	public static int getMajorJavaVersion() {
		String[] javaVersionElements = System.getProperty("java.version").split("\\.");
		return Integer.parseInt(javaVersionElements[1]);
	}
	
	public static int extractPort(String hostAndPort) {
		int port = -1;
		try {
			URI uri = new URI("test://" + hostAndPort);
			port = uri.getPort();
		} 
		catch (URISyntaxException ex) {
			return -1;
		}
		
		return isPortValid(port) ? port : -1;
	}
	
	public static String extractHost(String hostAndPort) {
		String host = null;
		try {
			URI uri = new URI("test://" + hostAndPort);
			host = uri.getHost();
		} 
		catch (URISyntaxException ex) {
			return null;
		}
		
		return host;
	}
	
	public static boolean isPortValid(int port) {
		return (port >= 0 && port <= 65535);
	}
	
	public static boolean checkHostString(String hostAndPort) {
		return (extractHost(hostAndPort) != null && extractPort(hostAndPort) != -1);
	}
	
	public static String getBGColorTag(Color c) {
		String hex = Integer.toHexString(c.getRGB()).substring(2).toUpperCase();
		return "<font style=\"background-color: " + hex + "\">";
	}
	
	public static String getFGColorTag(Color c) {
		String hex = Integer.toHexString(c.getRGB()).substring(2).toUpperCase();
		return "<font style=\"color: " + hex + "\">";
	}
	
	public static String getFontFamilyTag(Font font) {
		String tag = "<font style=\"font-family: " + font.getFamily() + "\">";
		return tag;
	}
	
	public static void saveHostlistToFile(String hostlist, File file) throws Exception {
		OutputStreamWriter osw = null;
        try {
        	FileOutputStream fos = new FileOutputStream(file); 
            osw = new OutputStreamWriter(fos, "UTF-8");
            osw.write(hostlist);
            osw.flush();
        } 
        catch (Exception e) {
        	throw e;
        }
        finally {
        	close(osw);
        }
	}
	
	/**
	 * @param hostlistToFill
	 * @param file
	 * @return 0 on success or the line number with the syntax error
	 * @throws Exception
	 */
	public static int loadHostlistFromFile(List<String> hostlistToFill, File file) throws Exception {
//		List<String> hostlist = new ArrayList<String>();
		BufferedReader br = null;
        try {
        	FileReader fileReader = new FileReader(file);
			br = new BufferedReader(fileReader);
			String line;
			int lineCounter = 1;
			while ((line = br.readLine()) != null) {
				if (checkHostString(line)) {
					hostlistToFill.add(line);	
				}
				else {
					return lineCounter;
				}
				lineCounter++;
			}
        } 
        catch (Exception e) {
        	throw e;
        }
        finally {
        	close(br);
        }
        
        return 0;
	}
	
	public static void saveCertificatesToDirectory(List<HostListItem> hostlist, File directory) throws Exception {
		FileOutputStream fos = null;
        try {
        	for (HostListItem host : hostlist) {
        		if (host.getScanTask() == null || host.getScanTask().getScanData().getCertAvailable() == false) {
        			continue;
        		}
        		
        		String id = host.getHost() + "_" + host.getPort();
        		File subDirectory = new File(directory.getPath() + File.separator + id);
        		subDirectory.mkdir();
        		
        		Cert[] certs = host.getScanTask().getScanData().certs;
        		for (int i = 0; i < certs.length; i++) {
        			Cert cert = certs[i];
        			String filename = "";
        			if (i == 0) {
        				filename = id + ".cert";
        			}
        			else {
        				filename = "issuer_" + i + ".cert";
        			}
        			
    	        	File file = new File(subDirectory.getPath() + File.separator + filename);
    	            byte[] buffer = cert.getCert().getEncoded();
    	            fos = new FileOutputStream(file);
    	            fos.write(buffer);
    	            fos.close();
    	            fos.flush();        			
        		}
        	}
        } 
        catch (Exception e) {
        	throw e;
        }
        finally {
        	close(fos);
        }
	}
	
	public static void close(Closeable closeable) {
    	if (closeable != null) {
    		try {
    			closeable.close();
    		}
    		catch (IOException e) {
    		}
    	}		
	}
	
	public static String bytesToHex(byte[] bytes, boolean addWhitespaces) {
		final char[] hexArray = "0123456789ABCDEF".toCharArray();
	    char[] hexChars = new char[bytes.length * 2];
	    for (int i = 0; i < bytes.length; i++) {
	        int v = bytes[i] & 0xFF;
	        hexChars[i * 2] = hexArray[v >>> 4];
	        hexChars[i * 2 + 1] = hexArray[v & 0x0F];
	    }
	    
	    if (addWhitespaces) {
	    	StringBuilder sb = new StringBuilder(128);
	    	for (int i = 0; i < hexChars.length; i++) {
	    		if (i % 2 == 0) {
	    			sb.append(hexChars[i]);
	    		}
	    		else {
	    			sb.append(hexChars[i] + " ");
	    		}
	    	}
	    	
	    	return sb.toString();
	    }
	    else {
	    	return new String(hexChars);	    	
	    }
	}
}
