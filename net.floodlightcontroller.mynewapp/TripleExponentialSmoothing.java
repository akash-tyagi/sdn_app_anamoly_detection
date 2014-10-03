package net.floodlightcontroller.mynewapp;

public class TripleExponentialSmoothing {

	public static double alpha = 0.1;
	public static double beta = 0.7;
	public static double gamma = 0.9;
	public static int totalForecasts = 1;
	public static int period = 2;

	public double[] forecast(int[] y) {

		if (y == null) {
			return null;
		}
		int seasons = y.length / period;
		// using simple technique to initiate InitialLevel
		double a0 = y[0];
		double b0 = calculateInitialTrend(y, period);
		double[] initialSeasonalIndices = calculateSeasonalIndices(y, period,
				seasons);
		double[] forecast = calculateHoltWinters(y, a0, b0,
				initialSeasonalIndices);
		return forecast;
	}

	private double[] calculateHoltWinters(int[] y, double a0, double b0,
			double[] initialSeasonalIndices) {
		double[] St = new double[y.length];
		double[] Bt = new double[y.length];
		double[] It = new double[y.length];
		double[] Ft = new double[y.length + totalForecasts];

		// Initialize base values
		St[1] = a0;
		Bt[1] = b0;
		for (int i = 0; i < period; i++) {
			It[i] = initialSeasonalIndices[i];
		}
		Ft[totalForecasts] = (St[0] + (totalForecasts * Bt[0])) * It[0];// This
																		// is
																		// actually
																		// 0
																		// since
																		// Bt[0]
		Ft[totalForecasts + 1] = (St[1] + (totalForecasts * Bt[1])) * It[1];// Forecast
																			// starts
																			// from
																			// period

		// Start calculations
		for (int i = 2; i < y.length; i++) {
			// Calculate overall smoothing
			if ((i - period) >= 0) {
				St[i] = alpha * y[i] / It[i - period] + (1.0 - alpha)
						* (St[i - 1] + Bt[i - 1]);
			} else {
				St[i] = alpha * y[i] + (1.0 - alpha) * (St[i - 1] + Bt[i - 1]);
			}
			// Calculate trend smoothing
			Bt[i] = gamma * (St[i] - St[i - 1]) + (1 - gamma) * Bt[i - 1];

			// Calculate seasonal smoothing
			if ((i - period) >= 0) {
				It[i] = beta * y[i] / St[i] + (1.0 - beta) * It[i - period];
			}

			// Calculate forecast
			if (((i + totalForecasts) >= period)) {
				Ft[i + totalForecasts] = (St[i] + (totalForecasts * Bt[i]))
						* It[i - period + totalForecasts];
			}
		}

		return Ft;
	}

	private double calculateInitialTrend(int[] y, int period) {

		double sum = 0;
		for (int i = 0; i < period; i++) {
			sum += (y[period + i] - y[i]);
		}
		return sum / (period * period);
	}

	private double[] calculateSeasonalIndices(int[] y, int period, int seasons) {

		double[] seasonalAverage = new double[seasons];
		double[] seasonalIndices = new double[period];
		double[] averagedObservations = new double[y.length];
		for (int i = 0; i < seasons; i++) {
			for (int j = 0; j < period; j++) {
				seasonalAverage[i] += y[(i * period) + j];
			}
			seasonalAverage[i] /= period;
		}
		for (int i = 0; i < seasons; i++) {
			for (int j = 0; j < period; j++) {
				averagedObservations[(i * period) + j] = y[(i * period) + j]
						/ seasonalAverage[i];
			}
		}
		for (int i = 0; i < period; i++) {
			for (int j = 0; j < seasons; j++) {
				seasonalIndices[i] += averagedObservations[(j * period) + i];
			}
			seasonalIndices[i] /= seasons;
		}
		return seasonalIndices;
	}
}
