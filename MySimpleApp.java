/*
 * This App is designed to capture the switch signatures
 */
package net.floodlightcontroller.mynewapp;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

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

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPortStatus;
import org.openflow.protocol.OFType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyNewApp implements IFloodlightModule, IOFMessageListener,
		MyNewAppService {
	public static int TIMEFRAME = 60;
	public static int PERIOD = 6;

	protected IFloodlightProviderService floodlightProvider;
	protected IRestApiService restApi;
	protected IDeviceService deviceManager;
	protected static Logger logger;

	class HostTrafficVector {
		long currSw;
		int[] ipFreq;
	}

	// If accessed by the REST API then need to be thread safe
	// as two threads may end up accessing it
	protected Map<Long, HostTrafficVector> macToTrafficVector;

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

		logger.info("PacketType:" + msg.getType());
		switch (msg.getType()) {
		case PACKET_IN:
			processPacketInMessage(sw, msg);
			break;
		default:
			break;
		}
		return Command.CONTINUE;
	}

	private void processPortStatusMessage(IOFSwitch sw, OFMessage msg) {
		OFPortStatus status = (OFPortStatus) msg;

	}

	private void processPacketInMessage(IOFSwitch sw, OFMessage msg) {
		OFPacketIn pi = (OFPacketIn) msg;
		// parse the data in packetIn using match
		OFMatch match = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), pi.getInPort());

		Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
		// Keys used to access the data in the map
		if (match.getDataLayerType() != Ethernet.TYPE_IPv4) {
			return;
		}

		// retrieve all known devices
		Collection<? extends IDevice> allDevices = deviceManager
				.getAllDevices();
		logger.info("---------------------------");
		for (IDevice d : allDevices) {
			if (sourceMac != d.getMACAddress()) {
				continue;
			}
			// Mac Address is Same
			logger.info("Device Mac Address:" + d.getMACAddress()
					+ " SouceMac:" + sourceMac);
			SwitchPort[] ports = d.getAttachmentPoints();
			for (int j = 0; j < ports.length; j++) {
				// Source switch and curent switch are same
				if (ports[j].getSwitchDPID() != sw.getId()) {
					continue;
				}
				logger.info("Switch DPID" + ports[j].getSwitchDPID()
						+ " SwitchID:" + sw.getId());

				Calendar calendar = Calendar.getInstance();
				int seconds = calendar.get(Calendar.SECOND);
				int index = seconds % PERIOD;
				// Insert frequency in the array
				if (!macToTrafficVector.containsKey(sourceMac)) {
					HostTrafficVector hostTrafficVector = new HostTrafficVector();
					hostTrafficVector.currSw = sw.getId();
					hostTrafficVector.ipFreq = new int[TIMEFRAME / PERIOD];
					for (int k = 0; k < TIMEFRAME / PERIOD; k++) {
						// We are initializing the array with some predefined
						// traffic for a period of 10 seconds. Hence, we are
						// expecting a minimum of 5 IP requests from 1 host in
						// this network
						hostTrafficVector.ipFreq[k] = 0;
					}
					hostTrafficVector.ipFreq[index] = 0;
					macToTrafficVector.put(sourceMac, hostTrafficVector);
				}
				macToTrafficVector.get(sourceMac).ipFreq[index]++;
			}
		}
		printTrafficVector();
	}

	private void printTrafficVector() {
		logger.info("*****************************************************");
		for (Long mac : macToTrafficVector.keySet()) {
			logger.info("---------------Mac:" + mac + "------------------");
			for (int i = 0; i < macToTrafficVector.get(mac).ipFreq.length; i++) {
				logger.info("---------------TimeFrame:" + i + "-" + (6 * i - 1)
						+ " Freq:" + macToTrafficVector.get(mac).ipFreq[i]);
			}
		}
		logger.info("*****************************************************");
	}

	// private void updateFreqIfNewSw(Long sourceMac, Long swId) {
	// // If the mac address is new then create new profile
	// if (!macToTrafficVector.containsKey(sourceMac)) {
	// logger.info("+++++++++++++++Adding new Host Profile " + sourceMac);
	// HostTrafficVector profile = new HostTrafficVector();
	// profile.currSw = -1;
	// profile.ipFreq = new HashMap<Long, Integer>();
	// profile.ipFreq.put(swId, 0);
	// macToTrafficVector.put(sourceMac, profile);
	// }
	// HostTrafficVector profile = macToTrafficVector.get(sourceMac);
	// long currSw = profile.currSw;
	// // If current switch is no more same. ie the host has moved
	// if (currSw != swId) {
	// if (!profile.ipFreq.containsKey(swId)) {
	// profile.ipFreq.put(swId, 0);
	// }
	// profile.currSw = swId;
	// int oldFreq = profile.ipFreq.get(swId);
	// profile.ipFreq.put(swId, oldFreq + 1);
	// }
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
		macToTrafficVector = new HashMap<>();
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
	public int getData() {
		return 124;
	}

}

