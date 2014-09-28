/*
 * This App is designed to capture the switch signatures
 */
package net.floodlightcontroller.mynewapp;

import java.util.ArrayList;
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
	protected IFloodlightProviderService floodlightProvider;
	protected IRestApiService restApi;
	protected IDeviceService deviceManager;
	protected static Logger logger;

	class HostProfileVector {
		long currSw;
		Map<Long, Integer> swFreq;
	}

	// If accessed by the REST API then need to be thread safe
	// as two threads may end up accessing it
	protected Map<Long, HostProfileVector> macToProfileVector;

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
		// retrieve all known devices
		Collection<? extends IDevice> allDevices = deviceManager
				.getAllDevices();
		for (IDevice d : allDevices) {
			logger.info("Device Mac Address:" + d.getMACAddressString());
			SwitchPort[] ports = d.getAttachmentPoints();
			for (int j = 0; j < ports.length; j++) {
				logger.info("Switch Connected:" + ports[j]);
			}
			// for (int j = 0; j < d.getIPv4Addresses().length; j++) {
			// if (srcDevice == null && client.ipAddress ==
			// d.getIPv4Addresses()[j])
			// srcDevice = d;
			// if (dstDevice == null && member.address ==
			// d.getIPv4Addresses()[j]) {
			// dstDevice = d;
			// member.macString = dstDevice.getMACAddressString();
			// }
			// if (srcDevice != null && dstDevice != null)
			// break;
			logger.info("Device Mac Address:" + d.getMACAddressString());
		}
		switch (msg.getType()) {
		case PACKET_IN:
			// processPacketInMessage(sw, msg);
			break;
		case PORT_STATUS:
			logger.info("-----------------------");
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

		logger.info("###Switch Id:" + sw.getId() + " Mac:" + sourceMac
				+ " BufferId:" + pi.getBufferId());
		updateFreqIfNewSw(sourceMac, sw.getId());
		printPofileVector();
	}

	private void updateFreqIfNewSw(Long sourceMac, Long swId) {
		// If the mac address is new then create new profile
		if (!macToProfileVector.containsKey(sourceMac)) {
			logger.info("+++++++++++++++Adding new Host Profile " + sourceMac);
			HostProfileVector profile = new HostProfileVector();
			profile.currSw = -1;
			profile.swFreq = new HashMap<Long, Integer>();
			profile.swFreq.put(swId, 0);
			macToProfileVector.put(sourceMac, profile);
		}
		HostProfileVector profile = macToProfileVector.get(sourceMac);
		long currSw = profile.currSw;
		// If current switch is no more same. ie the host has moved
		if (currSw != swId) {
			if (!profile.swFreq.containsKey(swId)) {
				profile.swFreq.put(swId, 0);
			}
			profile.currSw = swId;
			int oldFreq = profile.swFreq.get(swId);
			profile.swFreq.put(swId, oldFreq + 1);
		}
	}

	private void printPofileVector() {
		logger.info("*****************************************************");
		for (Long mac : macToProfileVector.keySet()) {
			logger.info("---------------Mac:" + mac + "------------------");
			for (Long swId : macToProfileVector.get(mac).swFreq.keySet()) {
				logger.info("---------------Switch:" + swId + " Freq:"
						+ macToProfileVector.get(mac).swFreq.get(swId));
			}
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
		macToProfileVector = new HashMap<>();
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

