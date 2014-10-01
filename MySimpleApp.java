/*
 * This App is designed to find the network traffic anomaly
 */
package net.floodlightcontroller.mynewapp;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.mactracker.MACTracker;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.restserver.IRestApiService;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.openflow.protocol.Wildcards;
import org.openflow.protocol.Wildcards.Flag;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyNewApp implements IFloodlightModule, IOFMessageListener,
		MyNewAppService {
	private static final short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 60;
	private static final short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0;
	public static final String HOST_STATUS_CONNECTED = "connected";
	public static final String HOST_STATUS_BLOCKED = "blocked";
	public static int TIMEFRAME = 60;
	public static int PERIOD = 3;

	protected IFloodlightProviderService floodlightProvider;
	protected IRestApiService restApi;
	protected IDeviceService deviceManager;
	protected static Logger logger;

	protected class HostTrafficVector {
		long currSw;
		int currFrame;
		int[] ipFreq;
		// current threshold value for the traffic for the host
		int threashold;
		// used to avoid multiple violation entry for the same time frame
		boolean violated;
	}

	// Map to store the violation data of each host
	ConcurrentMap<Long, HostViolationVector> violationMap;

	// If accessed by the REST API then need to be thread safe
	// as two threads may end up accessing it
	// Map to store the traffic corresponding to each host
	protected Map<Long, HostTrafficVector> macToTrafficVector;

	class Data {
		Long swId;
		short port;
		String status;

		public Long getSwId() {
			return swId;
		}

		public short getPort() {
			return port;
		}

		public String getStatus() {
			return status;
		}

	}

	// Map to store the status of all the hosts in the network
	protected Map<Long, Data> macStatusMap;

	public List<Long> macListToBlock;

	@Override
	public String getName() {
		return "MyNewApp";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		OFPacketIn pi = (OFPacketIn) msg;
		// parse the data in packetIn using match
		OFMatch match = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), pi.getInPort());
		// Add mac to the status map if not present
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		Long sourceMACHash = Ethernet.toLong(eth.getSourceMACAddress());
		if (!macStatusMap.containsKey(sourceMACHash)) {
			Data data = new Data();
			data.port = pi.getInPort();
			data.status = HOST_STATUS_CONNECTED;
			data.swId = sw.getId();
			macStatusMap.put(sourceMACHash, data);
		}

		blockHostForSwitch(sw);

		// logger.info("PacketType:" + msg.getType());
		switch (msg.getType()) {
		case PACKET_IN:
			processPacketInMessage(sw, msg);
			break;
		default:
			break;
		}
		return Command.CONTINUE;
	}

	private void blockHostForSwitch(IOFSwitch sw) {
		for (int i = 0; i < macListToBlock.size(); i++) {
			if (macStatusMap.get(macListToBlock.get(i)).swId != sw.getId()
					&& macStatusMap.get(macListToBlock.get(i)).status == HOST_STATUS_BLOCKED) {
				continue;
			}
			// Block the host
			OFFlowMod rule = new OFFlowMod();
			rule.setType(OFType.FLOW_MOD);
			rule.setCommand(OFFlowMod.OFPFC_ADD);
			rule.setPriority((short) 100);
			OFMatch match = new OFMatch();
			match.setWildcards(Wildcards.FULL.matchOn(Flag.DL_SRC));
			match.setDataLayerSource(Ethernet.toByteArray(macListToBlock.get(i)));

			rule.setMatch(match);
			rule.setIdleTimeout(MyNewApp.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
			rule.setHardTimeout(MyNewApp.FLOWMOD_DEFAULT_HARD_TIMEOUT);
			ArrayList<OFAction> actions = new ArrayList<OFAction>();
			OFAction outputTo = new OFActionOutput();
			actions.add(outputTo);
			rule.setActions(actions);

			// specify the length of the flow structure created
			rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));

			logger.debug("install rule for  mac address{}",
					HexString.toHexString(macListToBlock.get(i)));
			try {
				sw.write(rule, null);
				logger.info("Rule installation successfull");
				macStatusMap.get(macListToBlock.get(i)).status = HOST_STATUS_BLOCKED;

			} catch (Exception e) {
				logger.error("Rule installation failed");
				e.printStackTrace();
			}
		}
	}

	private void processPacketInMessage(IOFSwitch sw, OFMessage msg) {
		OFPacketIn pi = (OFPacketIn) msg;
		// parse the data in packetIn using match
		OFMatch match = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), pi.getInPort());
		Long sourceMac = Ethernet.toLong(match.getDataLayerSource());

		if (match.getDataLayerType() != Ethernet.TYPE_IPv4) {
			return;
		}

		// retrieve all known devices and find the position of source device
		Collection<? extends IDevice> allDevices = deviceManager
				.getAllDevices();
		// logger.info("---------------------------");
		for (IDevice d : allDevices) {
			if (sourceMac != d.getMACAddress()) {
				continue;
			}
			// Mac Address of device and source mac matches
			// logger.info("Device Mac Address:" + d.getMACAddress()
			// + " SouceMac:" + sourceMac);
			SwitchPort[] ports = d.getAttachmentPoints();
			for (int j = 0; j < ports.length; j++) {
				// Source switch and current switch are same
				if (ports[j].getSwitchDPID() != sw.getId()) {
					continue;
				}
				logger.info("Switch DPID" + ports[j].getSwitchDPID()
						+ " SwitchID:" + sw.getId());
				updateTrafficCount(sourceMac, sw);
			}
		}
		// printTrafficVector();
	}

	private void updateTrafficCount(Long sourceMac, IOFSwitch sw) {
		Calendar calendar = Calendar.getInstance();
		int seconds = calendar.get(Calendar.SECOND);
		int index = seconds / PERIOD;
		// Insert frequency in the array
		if (!macToTrafficVector.containsKey(sourceMac)) {
			initializeMapForNewHost(sourceMac, sw, index);
		}
		// Moved to the new Time Frame. Thus do 2 things
		// 1.Reset the value in the current time frame
		// 2.Calculate the threshold value of this time frame
		if (index != macToTrafficVector.get(sourceMac).currFrame) {
			macToTrafficVector.get(sourceMac).currFrame = index;
			macToTrafficVector.get(sourceMac).ipFreq[index] = 0;
			macToTrafficVector.get(sourceMac).violated = false;
			calculateNewThreashold(sourceMac, index);
		}
		macToTrafficVector.get(sourceMac).ipFreq[index]++;
		// Threshold Violated, insert an entry in the ViolationMap against the
		// mac address
		if (macToTrafficVector.get(sourceMac).threashold < macToTrafficVector
				.get(sourceMac).ipFreq[index]
				&& macToTrafficVector.get(sourceMac).violated == false) {
			macToTrafficVector.get(sourceMac).violated = true;
			logger.info("WARNING::::: THIS IS GETTING HOT:: Expected"
					+ macToTrafficVector.get(sourceMac).threashold + " Actual:"
					+ macToTrafficVector.get(sourceMac).ipFreq[index]);

			updateViolationData(sourceMac);
		}
	}

	private void updateViolationData(Long sourceMac) {
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		Calendar cal = Calendar.getInstance();
		ViolationData violationData = new ViolationData();
		violationData
				.setThreashold(macToTrafficVector.get(sourceMac).threashold);
		violationData.setActual(macToTrafficVector.get(sourceMac).threashold);
		violationData.setTime(dateFormat.format(cal.getTime()));
		if (!violationMap.containsKey(sourceMac)) {
			HostViolationVector violationVector = new HostViolationVector();
			violationVector.macAddress = HexString.toHexString(sourceMac);
			violationVector.violations = Collections
					.synchronizedList(new ArrayList<ViolationData>());
			violationMap.put(sourceMac, violationVector);
		}
		// Need to check the concurrency working
		violationMap.get(sourceMac).violations.add(violationData);
	}

	private void calculateNewThreashold(Long sourceMac, int index) {
		int size = 10;// (TIMEFRAME / PERIOD) - 1;
		int[] y = new int[size];
		int j = 0;
		int k = index + 1;
		while (j < size) {
			y[j++] = macToTrafficVector.get(sourceMac).ipFreq[k % PERIOD];
			k++;
		}
		double[] forecast = HoltWintersTripleExponentialImpl.forecast(y, false);
		macToTrafficVector.get(sourceMac).threashold = (int) (forecast[forecast.length - 1] + 0.5);
		logger.info("New Threashold value is:"
				+ macToTrafficVector.get(sourceMac).threashold);
	}

	private void initializeMapForNewHost(Long sourceMac, IOFSwitch sw, int index) {
		HostTrafficVector hostTrafficVector = new HostTrafficVector();
		hostTrafficVector.currSw = sw.getId();
		hostTrafficVector.ipFreq = new int[TIMEFRAME / PERIOD];
		for (int k = 0; k < TIMEFRAME / PERIOD; k++) {
			// We are initializing the array with some predefined
			// traffic for a period of 10 seconds. Hence, we are
			// expecting a minimum of 5 IP requests from 1 host in
			// this network
			hostTrafficVector.ipFreq[k] = 1;
		}
		hostTrafficVector.ipFreq[index] = 0;
		hostTrafficVector.currFrame = index;
		hostTrafficVector.violated = false;
		macToTrafficVector.put(sourceMac, hostTrafficVector);
	}

	private void printTrafficVector() {
		logger.info("*****************************************************");
		for (Long mac : macToTrafficVector.keySet()) {
			logger.info("---------------Mac:" + mac + "------------------");
			for (int i = 0; i < macToTrafficVector.get(mac).ipFreq.length; i++) {
				logger.info("---------------TimeFrame:" + i + " Freq:"
						+ macToTrafficVector.get(mac).ipFreq[i]);
			}
			return;
		}
		logger.info("*****************************************************");
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(MyNewAppService.class);
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		m.put(MyNewAppService.class, this);
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IRestApiService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		restApi = context.getServiceImpl(IRestApiService.class);
		deviceManager = context.getServiceImpl(IDeviceService.class);
		macToTrafficVector = new HashMap<>();
		violationMap = new ConcurrentHashMap<>();
		macStatusMap = new ConcurrentHashMap<>();
		macListToBlock = Collections.synchronizedList(new ArrayList<Long>());
		logger = LoggerFactory.getLogger(MACTracker.class);

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFMessageListener(OFType.PORT_STATUS, this);
		restApi.addRestletRoutable(new MyNewAppWebRoutable());
	}

	@Override
	public ConcurrentMap<Long, HostViolationVector> getViolationData() {
		return violationMap;
	}

	@Override
	public Map<Long, Data> getDeviceStatus() {
		return macStatusMap;
	}

	public List<Long> getListToBlock() {
		return macListToBlock;
	}

}

