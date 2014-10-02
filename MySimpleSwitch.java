package net.floodlightcontroller.simpleswitch;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.mactracker.MACTracker;
import net.floodlightcontroller.mynewapp.MyNewApp;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

import org.openflow.protocol.OFFlowMod;
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
import org.openflow.util.U16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MySimpleSwitch implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;
	protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 500; // in seconds
	protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite

	class Data {
		long swId;
		long mac;
		short outputPort;
	}

	class Info {
		int sourceIp;
		int destinationIp;
		short outputPort;
	}

	// If accessed by the REST API then need to be thread safe
	// as two threads may end up accessing it
	protected Map<Integer, Data> ipToSwitch;
	protected Map<Long, Map<String, Info>> switchToRuleMap;

	@Override
	public String getName() {
		return MySimpleSwitch.class.getSimpleName();
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

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		ipToSwitch = new HashMap<>();
		switchToRuleMap = new HashMap<>();
		logger = LoggerFactory.getLogger(MACTracker.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		OFPacketIn pi = (OFPacketIn) msg;
		// parse the data in packetIn using match
		OFMatch match = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), pi.getInPort());

		Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
		Long destMac = Ethernet.toLong(match.getDataLayerDestination());
		int destIP = match.getNetworkDestination();
		int sourceIP = match.getNetworkSource();
		Short inputPort = pi.getInPort();
		long swId = sw.getId();

		if (!ipToSwitch.containsKey(sourceIP)) {
			logger.info("Adding ip +++++++++++++++"
					+ IPv4.fromIPv4Address(sourceIP));
			Data data = new Data();
			data.mac = sourceMac;
			data.outputPort = inputPort;
			data.swId = sw.getId();
			ipToSwitch.put(sourceIP, data);
		}

		if (destIP != 0) {
			String key = destIP + ":" + sourceIP;
			if (!switchToRuleMap.containsKey(swId)) {
				Map<String, Info> map = new HashMap<>();
				switchToRuleMap.put(swId, map);
			}
			if (!switchToRuleMap.get(swId).containsKey(key)) {
				Info info = new Info();
				info.sourceIp = destIP;
				info.destinationIp = sourceIP;
				info.outputPort = inputPort;
				switchToRuleMap.get(swId).put(key, info);
				installIpAndArpRules(sw, info);
			}

		}
		logger.info("Flooding");
		this.pushPacket(sw, match, pi, (short) OFPort.OFPP_FLOOD.getValue());
		return Command.CONTINUE;
	}

	private void installIpAndArpRules(IOFSwitch sw, Info info) {

		// create the rule
		OFFlowMod rule = new OFFlowMod();
		setBasicPropForRule(rule);
		// set the Flow Removed bit
		rule.setFlags(OFFlowMod.OFPFF_SEND_FLOW_REM);

		// set of actions to apply to this rule
		ArrayList<OFAction> actions = new ArrayList<OFAction>();
		OFAction outputTo = new OFActionOutput(info.outputPort);
		actions.add(outputTo);

		// Match for ARP packet rule
		OFMatch match = new OFMatch();
		match.setNetworkSource(info.sourceIp);
		match.setNetworkDestination(info.destinationIp);

		match.setDataLayerType(Ethernet.TYPE_ARP);
		match.setWildcards(Wildcards.FULL.matchOn(Flag.DL_TYPE)
				.matchOn(Flag.NW_SRC).matchOn(Flag.NW_DST).withNwSrcMask(32)
				.withNwDstMask(32));
		sendFlowMod(sw, rule, actions, match);

		// Installing IP packet rule
		match.setDataLayerType(Ethernet.TYPE_IPv4);
		match.setNetworkProtocol(IPv4.PROTOCOL_ICMP);
		match.setWildcards(Wildcards.FULL.matchOn(Flag.DL_TYPE)
				.matchOn(Flag.NW_PROTO).matchOn(Flag.NW_SRC)
				.matchOn(Flag.NW_DST).withNwSrcMask(32).withNwDstMask(32));
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
		rule.setType(OFType.FLOW_MOD);
		rule.setCommand(OFFlowMod.OFPFC_ADD);
		// specify timers for the life of the rule
		rule.setIdleTimeout(MySimpleSwitch.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
		rule.setHardTimeout(MySimpleSwitch.FLOWMOD_DEFAULT_HARD_TIMEOUT);
		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		// specify the length of the flow structure created
		rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
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

		// set data if it is included in the packet in but buffer id is NONE
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

}

