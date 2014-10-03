/*
 * This App is designed to find the network traffic anomaly
 */
package net.floodlightcontroller.mynewapp;

import java.io.IOException;
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
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.mactracker.MACTracker;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.restserver.IRestApiService;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFFlowRemoved;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.Wildcards;
import org.openflow.protocol.Wildcards.Flag;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.HexString;
import org.openflow.util.U16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyNewApp implements IFloodlightModule, IOFMessageListener,
		MyNewAppService {
	private static final short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 8;
	private static final short FLOWMOD_DEFAULT_HARD_TIMEOUT = 8;

	// Total time to be considered ( in seconds)
	public static int TIMEWINDOW = 60;
	// Number of time frames in which the Timewindow will be divided
	public static int PERIOD = 6;
	// Used to define the width of the confidence band
	public static int SCALING_FACTOR = 2;
	// threshold value for the violations for single host
	public static int THRESHOLD = 1;

	protected IFloodlightProviderService floodlightProvider;
	protected IRestApiService restApi;
	protected IDeviceService deviceManager;
	protected static Logger logger;

	protected class HostTrafficVector {
		// switch to which the host is attached
		long currSw;
		// index of curr frame
		int currFrame;
		// freq in a current time frame
		int[] icmpPacketFreq;
		// current predicted value for the traffic for the host
		int prediction;
		// used to avoid multiple violation entry for the same time frame
		boolean violated;
	}

	// Map to store the violation data of each host
	ConcurrentMap<Long, HostViolationVector> violationMap;

	// Map to store the ICMP traffic information of each host
	protected Map<Long, HostTrafficVector> macToTrafficVector;

	class HostConnectionData {
		public static final String HOST_STATUS_CONNECTED = "CONNECTED";
		public static final String HOST_STATUS_BLOCKED = "BLOCKED";

		Long switchId;
		short port;
		String status;

		public Long getSwId() {
			return switchId;
		}

		public short getPort() {
			return port;
		}

		public String getStatus() {
			return status;
		}

	}

	class Data {
		long swId;
		long mac;
		short port;
	}

	class Info {
		int sourceIp;
		short port;
	}

	protected Map<Integer, Data> ipToSwitch;
	protected Map<Long, Map<Integer, Info>> switchToHost;

	// Map to store the status of all the hosts in the network
	protected Map<Long, HostConnectionData> hostStatusMap;

	// mac address of host to block in the network
	public List<Long> hostListToBlock;

	@Override
	public String getName() {
		return MyNewApp.class.getSimpleName();
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

		logger.info("--------------------------------------------------------");
		switch (msg.getType()) {
		case PACKET_IN:
			logger.info("PacketIn Path...");
			return processPacketInMessage(sw, (OFPacketIn) msg);
		case FLOW_REMOVED:
			return processFlowRemovedMessage(sw, (OFFlowRemoved) msg);
		default:
			break;
		}

		return Command.CONTINUE;
	}

	private Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi) {
		// parse the data in packetIn using match
		OFMatch match = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), pi.getInPort());

		Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
		int destIP = match.getNetworkDestination();
		int sourceIP = match.getNetworkSource();
		Short inputPort = pi.getInPort();
		long swId = sw.getId();

		logger.info("Souce IP:" + IPv4.fromIPv4Address(sourceIP)
				+ "  -- Destn IP: " + IPv4.fromIPv4Address(destIP)
				+ " -- Source MAcAdress:" + sourceMac);

		if (match.getNetworkSource() != 0 && !ipToSwitch.containsKey(sourceIP)) {
			logger.info("Adding ip +++++++++++++++"
					+ IPv4.fromIPv4Address(sourceIP));
			Data data = new Data();
			data.mac = sourceMac;
			data.port = inputPort;
			data.swId = sw.getId();
			ipToSwitch.put(sourceIP, data);
			initMaps(sw, match, inputPort);
			// installRuleForMonitoring(sw, sourceIP);
		}

		if (destIP != 0) {
			if (!switchToHost.containsKey(swId)) {
				Map<Integer, Info> map = new HashMap<>();
				switchToHost.put(swId, map);
			}
			if (!switchToHost.get(swId).containsKey(sourceIP)) {
				Info info = new Info();
				info.sourceIp = sourceIP;
				info.port = inputPort;
				switchToHost.get(swId).put(sourceIP, info);
			}

			if (switchToHost.get(swId).containsKey(destIP)
					&& (match.getDataLayerType() == Ethernet.TYPE_ARP)
					|| match.getDataLayerType() == Ethernet.TYPE_IPv4) {
				installRule(sw, match);
				OFMatch reverseMatch = match
						.clone()
						.setDataLayerSource(match.getDataLayerDestination())
						.setDataLayerDestination(match.getDataLayerSource())
						.setNetworkSource(match.getNetworkDestination())
						.setNetworkDestination(match.getNetworkSource())
						.setInputPort(
								switchToHost.get(sw.getId()).get(
										match.getNetworkDestination()).port);
				installRule(sw, reverseMatch);
			}

		}
		logger.info("Flooding");
		this.pushPacket(sw, match, pi, (short) OFPort.OFPP_FLOOD.getValue());
		return Command.CONTINUE;
	}

	private void installRule(IOFSwitch sw, OFMatch match) {
		short outPort = switchToHost.get(sw.getId()).get(
				match.getNetworkDestination()).port;

		// create the rule
		OFFlowMod rule = (OFFlowMod) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.FLOW_MOD);
		setBasicPropForRule(rule);
		// set the Flow Removed bit
		rule.setFlags(OFFlowMod.OFPFF_SEND_FLOW_REM);

		// set of actions to apply to this rule
		ArrayList<OFAction> actions = new ArrayList<OFAction>();
		OFAction outputTo = new OFActionOutput(outPort);
		actions.add(outputTo);

		match.setWildcards(Wildcards.FULL.matchOn(Flag.DL_TYPE)
				.matchOn(Flag.IN_PORT).withNwSrcMask(32).withNwDstMask(32));
		sendFlowMod(sw, rule, actions, match);
	}

	private void sendFlowMod(IOFSwitch sw, OFFlowMod rule,
			ArrayList<OFAction> actions, OFMatch match) {
		rule.setMatch(match);
		rule.setActions(actions);

		try {
			sw.write(rule, null);
			logger.info("Rule installation successfull");
		} catch (Exception e) {
			logger.error("Rule installation failed");
			e.printStackTrace();
		}
	}

	private void setBasicPropForRule(OFFlowMod rule) {
		rule.setCommand(OFFlowMod.OFPFC_ADD);
		rule.setFlags(OFFlowMod.OFPFF_SEND_FLOW_REM);
		// specify timers for the life of the rule
		rule.setIdleTimeout(MyNewApp.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
		rule.setHardTimeout(MyNewApp.FLOWMOD_DEFAULT_HARD_TIMEOUT);
		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		// specify the length of the flow structure created
		rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
	}

	private void initMaps(IOFSwitch sw, OFMatch match, Short inputPort) {
		Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
		int sourceIP = match.getNetworkSource();

		Data data = new Data();
		data.mac = sourceMac;
		data.port = inputPort;
		data.swId = sw.getId();
		ipToSwitch.put(sourceIP, data);

		// Initializing Traffic map for the host
		Calendar calendar = Calendar.getInstance();
		int seconds = calendar.get(Calendar.SECOND);
		int timeFrame = seconds / PERIOD;
		// Insert frequency in the array
		if (!macToTrafficVector.containsKey(sourceMac)) {
			initializeMapForNewHost(sourceMac, sw, timeFrame);
		}

		// Initializing Violation Map for host
		if (!violationMap.containsKey(sourceMac)) {
			HostViolationVector violationVector = new HostViolationVector();
			violationVector.macAddress = HexString.toHexString(sourceMac);
			violationVector.violations = Collections
					.synchronizedList(new ArrayList<ViolationData>());
			violationMap.put(sourceMac, violationVector);
		}

		// Initializing the status map
		if (!hostStatusMap.containsKey(sourceMac)) {
			HostConnectionData connectionData = new HostConnectionData();
			connectionData.status = HostConnectionData.HOST_STATUS_CONNECTED;
			connectionData.switchId = sw.getId();
			connectionData.port = inputPort;
			hostStatusMap.put(sourceMac, connectionData);
		}
	}

	private void pushPacket(IOFSwitch sw, OFMatch match, OFPacketIn pi,
			short outport) {

		// create an OFPacketOut for the pushed packet
		OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.PACKET_OUT);

		// update the inputPort and bufferID
		po.setInPort(pi.getInPort());
		po.setBufferId(pi.getBufferId());

		// define the actions to apply for this packet
		OFActionOutput action = new OFActionOutput();
		action.setPort(outport);
		po.setActions(Collections.singletonList((OFAction) action));
		po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);

		// set data if it is included in the packet in but buffer id is NONEf
		if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
			byte[] packetData = pi.getPacketData();
			po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
					+ po.getActionsLength() + packetData.length));
			po.setPacketData(packetData);
		} else {
			po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
					+ po.getActionsLength()));
		}

		// push the packet to the switch
		try {
			sw.write(po, null);
		} catch (IOException e) {
			logger.error("failed to write packetOut: ", e);
		}
	}

	private net.floodlightcontroller.core.IListener.Command processFlowRemovedMessage(
			IOFSwitch sw, OFFlowRemoved msg) {
		OFMatch match = msg.getMatch();

		logger.info("Flow Removed ----------------------------: " + msg);
		logger.info("Source Mac "
				+ HexString.toHexString(match.getDataLayerSource()) + " dest "
				+ HexString.toHexString(match.getDataLayerDestination())
				+ " sour ip " + IPv4.fromIPv4Address(match.getNetworkSource())
				+ " destn ip"
				+ IPv4.fromIPv4Address(match.getNetworkDestination()));
		int srcIp = match.getNetworkSource();

		if (srcIp == 0 || !ipToSwitch.containsKey(srcIp)
				|| ipToSwitch.get(srcIp).swId != sw.getId()
				|| match.getDataLayerType() != Ethernet.TYPE_IPv4
				|| match.getDataLayerType() == Ethernet.TYPE_ARP) {
			blockHostForSwitch(sw);
			return Command.CONTINUE;
		}

		logger.info("On Ip level");
		Long sourceMac = ipToSwitch.get(match.getNetworkSource()).mac;
		long count = msg.getPacketCount();
		// Flow-mod remove message will be from the same switch on which our
		// host is attached. Because our switch works on the same principle of
		// attaching rule to a host on the same router
		updateTrafficCount(sourceMac, sw, count);
		blockHostForSwitch(sw);
		// printTrafficVector();
		return Command.CONTINUE;
	}

	private void blockHostForSwitch(IOFSwitch sw) {
		for (int i = 0; i < hostListToBlock.size(); i++) {
			if (hostStatusMap.get(hostListToBlock.get(i)).switchId != sw
					.getId()
					&& hostStatusMap.get(hostListToBlock.get(i)).status == HostConnectionData.HOST_STATUS_BLOCKED) {
				continue;
			}
			long macToBlock = hostListToBlock.get(i);
			violationMap.get(macToBlock).violations = Collections
					.synchronizedList(new ArrayList<ViolationData>());
			logger.info("Sending blocking Rule for source "
					+ HexString.toHexString(macToBlock));
			// Block the host
			OFFlowMod rule = (OFFlowMod) floodlightProvider
					.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
			setBasicPropForRule(rule);
			rule.setPriority((short) 100);

			OFMatch match = new OFMatch();
			match.setDataLayerSource(Ethernet.toByteArray(macToBlock));
			match.setWildcards(Wildcards.FULL.matchOn(Flag.DL_SRC));

			ArrayList<OFAction> actions = new ArrayList<OFAction>();
			OFAction outputTo = new OFActionOutput();
			actions.add(outputTo);

			sendFlowMod(sw, rule, actions, match);
			hostStatusMap.get(macToBlock).status = HostConnectionData.HOST_STATUS_BLOCKED;
		}
	}

	private void checkAndAddMacToBlock(long mac) {
		if (violationMap.get(mac).violations.size() <= THRESHOLD) {
			return;
		}
		logger.info("!!!!!!!!!!!!!!!Mac:" + mac
				+ " has reached the threshold limit Blocking");
		hostListToBlock.add(mac);
	}

	private void updateTrafficCount(Long sourceMac, IOFSwitch sw, long count) {
		Calendar calendar = Calendar.getInstance();
		int seconds = calendar.get(Calendar.SECOND);
		int timeFrame = seconds / PERIOD;
		// Moved to the new Time Frame. And do 2 things
		// 1.Reset the value in the current time frame
		// 2.Calculate the threshold value of this time frame
		if (timeFrame != macToTrafficVector.get(sourceMac).currFrame) {
			macToTrafficVector.get(sourceMac).currFrame = timeFrame;
			macToTrafficVector.get(sourceMac).icmpPacketFreq[timeFrame] = 0;
			macToTrafficVector.get(sourceMac).violated = false;
			macToTrafficVector.get(sourceMac).prediction = predictTrafficForNextPeriod(
					sourceMac, timeFrame);
			logger.info("Prediction value is:"
					+ macToTrafficVector.get(sourceMac).prediction);
		}
		macToTrafficVector.get(sourceMac).icmpPacketFreq[timeFrame] += count;
		checkAndUpdateTrafficViolation(sourceMac, timeFrame);
	}

	private void checkAndUpdateTrafficViolation(Long sourceMac, int timeFrame) {
		// Confidence Bands are calculated for measuring Deviation
		int diff = (macToTrafficVector.get(sourceMac).icmpPacketFreq[timeFrame])
				- (SCALING_FACTOR * macToTrafficVector.get(sourceMac).prediction);

		if (diff > 0 && macToTrafficVector.get(sourceMac).violated == false) {
			macToTrafficVector.get(sourceMac).violated = true;
			logger.info("WARNING:::::: Expected"
					+ macToTrafficVector.get(sourceMac).prediction
					+ " Actual:"
					+ macToTrafficVector.get(sourceMac).icmpPacketFreq[timeFrame]);

			updateViolationData(sourceMac, timeFrame);
			checkAndAddMacToBlock(sourceMac);
		}
	}

	private void updateViolationData(Long sourceMac, int timeFrame) {
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		Calendar cal = Calendar.getInstance();
		ViolationData violationData = new ViolationData();
		violationData
				.setPredicted(macToTrafficVector.get(sourceMac).prediction);
		violationData
				.setActual(macToTrafficVector.get(sourceMac).icmpPacketFreq[timeFrame]);
		violationData.setTime(dateFormat.format(cal.getTime()));
		violationMap.get(sourceMac).violations.add(violationData);
	}

	private int predictTrafficForNextPeriod(Long sourceMac, int timeFrame) {
		int size = (TIMEWINDOW / PERIOD) - 1;
		int[] y = new int[size];
		int j = 0;
		int l = timeFrame + 1;
		while (j < size) {
			y[j++] = macToTrafficVector.get(sourceMac).icmpPacketFreq[l
					% PERIOD];
			l++;
		}
		logger.info("Values used for prediction for sourceMac "
				+ HexString.toHexString(sourceMac) + " with index " + timeFrame);
		for (int k = 0; k < y.length; k++) {
			System.out.print(y[k] + " ");
		}
		double[] forecast = new TripleExponentialSmoothing().forecast(y);
		return (int) (forecast[forecast.length - 1] + 0.5);
	}

	private void initializeMapForNewHost(Long sourceMac, IOFSwitch sw, int index) {
		HostTrafficVector hostTrafficVector = new HostTrafficVector();
		hostTrafficVector.currSw = sw.getId();
		hostTrafficVector.icmpPacketFreq = new int[TIMEWINDOW / PERIOD];
		for (int k = 0; k < TIMEWINDOW / PERIOD; k++) {
			// We are initializing the array with some predefined
			// traffic for a period of 10 seconds. Hence, we are
			// expecting a minimum of 3 IP requests from 1 host in
			// this network
			hostTrafficVector.icmpPacketFreq[k] = 3;
		}
		hostTrafficVector.icmpPacketFreq[index] = 0;
		hostTrafficVector.currFrame = index;
		hostTrafficVector.violated = false;
		macToTrafficVector.put(sourceMac, hostTrafficVector);
	}

	// private void printTrafficVector() {
	// logger.info("*****************************************************");
	// for (Long mac : macToTrafficVector.keySet()) {
	// logger.info("---------------Mac:" + mac + "------------------");
	// for (int i = 0; i < macToTrafficVector.get(mac).icmpPacketFreq.length;
	// i++) {
	// logger.info("---------------TimeFrame:" + i + " Freq:"
	// + macToTrafficVector.get(mac).icmpPacketFreq[i]);
	// }
	// return;
	// }
	// logger.info("*****************************************************");
	// }

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
		macToTrafficVector = new ConcurrentHashMap<>();
		violationMap = new ConcurrentHashMap<>();
		hostStatusMap = new ConcurrentHashMap<>();
		hostListToBlock = Collections.synchronizedList(new ArrayList<Long>());
		ipToSwitch = new HashMap<>();
		switchToHost = new HashMap<>();
		logger = LoggerFactory.getLogger(MACTracker.class);

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFMessageListener(OFType.FLOW_REMOVED, this);
		restApi.addRestletRoutable(new MyNewAppWebRoutable());
	}

	@Override
	public ConcurrentMap<Long, HostViolationVector> getViolationData() {
		return violationMap;
	}

	@Override
	public Map<Long, HostConnectionData> getHostStatusMap() {
		return hostStatusMap;
	}

	public List<Long> getListToBlock() {
		return hostListToBlock;
	}

}

