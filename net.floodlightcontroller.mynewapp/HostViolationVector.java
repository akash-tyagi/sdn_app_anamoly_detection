package net.floodlightcontroller.mynewapp;

import java.util.List;

public class HostViolationVector {

	String macAddress;
	List<ViolationData> violations;

	public List<ViolationData> getViolations() {
		return violations;
	}

	public void setViolations(List<ViolationData> violations) {
		this.violations = violations;
	}

	public boolean addNewViolation(ViolationData data) {
		return violations.add(data);
	}

	public String getMacAddress() {
		return macAddress;
	}

	public void setMacAddress(String macAddress) {
		this.macAddress = macAddress;
	}
}

