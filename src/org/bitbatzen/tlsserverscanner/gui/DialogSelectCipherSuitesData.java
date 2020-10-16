package org.bitbatzen.tlsserverscanner.gui;

import java.util.ArrayList;
import java.util.List;


public class DialogSelectCipherSuitesData {

	public boolean toggleAllSelected = false;
	public boolean selectFilteredSelected = false;
	public String filterSting = "";
	public List<String> selectedCipherSuites = new ArrayList<>();
}
