package net.floodlightcontroller.mynewapp;

public class ViolationData {
	String time;

	public String getTime() {
		return time;
	}

	public void setTime(String time) {
		this.time = time;
	}

	public int getThreashold() {
		return predicted;
	}

	public void setPredicted(int predicted) {
		this.predicted = predicted;
	}

	public int getActual() {
		return actual;
	}

	public void setActual(int actual) {
		this.actual = actual;
	}

	int predicted;
	int actual;
}

