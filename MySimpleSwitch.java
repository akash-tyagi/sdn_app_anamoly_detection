package net.floodlightcontroller.simpleswitch;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
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
import net.floodlightcontroller.mactracker.MACTracker;
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
	protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 60; // in seconds
	protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite

	class Data {
		Long swId;
		Long mac;
		short port;
	}

	// If accessed by the REST API then need to be thread safe
	// as two threads may end up accessing it
	protected Map<Integer, Data> ipToSwitch;

	@Override
	public String getName() {
		return MACTracker.class.getSimpleName();
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

		logger.info("-------------------------------------------------------");
		logger.info("Souce IP:" + IPv4.fromIPv4Address(sourceIP)
				+ "  -- Destn IP: " + IPv4.fromIPv4Address(destIP)
				+ " -- Source MAcAdress:" + sourceMac + " -- Dest MAcAdress:"
				+ destMac);

		if (match.getNetworkSource() != 0 && !ipToSwitch.containsKey(sourceIP)) {
			logger.info("Adding ip +++++++++++++++"
					+ IPv4.fromIPv4Address(sourceIP));
			Data data = new Data();
			data.mac = sourceMac;
			data.port = inputPort;
			data.swId = sw.getId();
			ipToSwitch.put(sourceIP, data);
		}
		// If packet type is ARP then simply allow the switch function normally
		// TODO:Not using this info although getting the sender IP and mac
		// address info
		if (match.getDataLayerType() == Ethernet.TYPE_ARP) {
			logger.info("ARPPPPPPPPPPPPPPPPPPPPPPP");
			return this.hubLogic(sw, (OFPacketIn) msg, match);
		}

		// If packet not IPV4 just resume the process and do not process
		if (match.getDataLayerType() != Ethernet.TYPE_IPv4) {
			return Command.CONTINUE;
		}

		Short outPort = null;
		if (ipToSwitch.containsKey(destIP)) {
			outPort = ipToSwitch.get(destIP).port;
		}

		if (outPort == null) {
			logger.info("Floddin%%%%%%%g");
			this.pushPacket(sw, match, pi, (short) OFPort.OFPP_FLOOD.getValue());
		} else {

			if (ipToSwitch.get(sourceIP).swId != ipToSwitch.get(destIP).swId) {
				logger.info("Not Same-------------------Flodding%%%%%"
						+ ipToSwitch.get(sourceIP).swId + ":"
						+ ipToSwitch.get(destIP).swId);
				return this.hubLogic(sw, pi, match);
			}
			logger.info("Installing rule %%%%%%");
			// otherwise install a rule s.t. all the traffic with the
			// destination
			// destMac should be forwarded on outPort

			// create the rule and specify it's an ADD rule
			OFFlowMod rule = new OFFlowMod();
			rule.setType(OFType.FLOW_MOD);
			rule.setCommand(OFFlowMod.OFPFC_ADD);

			// specify that all fields except destMac to be wildcard
			match = new OFMatch();
			match.setNetworkSource(sourceIP); // (1)
			match.setNetworkDestination(destIP); // (2)
			match.setDataLayerType(Ethernet.TYPE_IPv4);
			match.setNetworkProtocol(IPv4.PROTOCOL_ICMP);
			match.setWildcards(Wildcards.FULL.matchOn(Flag.DL_TYPE)
					.matchOn(Flag.NW_PROTO).withNwSrcMask(32).withNwDstMask(32));
			rule.setMatch(match);

			// specify timers for the life of the rule
			rule.setIdleTimeout(MySimpleSwitch.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
			rule.setHardTimeout(MySimpleSwitch.FLOWMOD_DEFAULT_HARD_TIMEOUT);

			// set the buffer id to NONE - implementation artifact
			rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);

			// set of actions to apply to this rule
			ArrayList<OFAction> actions = new ArrayList<OFAction>();
			OFAction outputTo = new OFActionOutput(outPort);
			actions.add(outputTo);
			rule.setActions(actions);

			// specify the length of the flow structure created
			rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));

			logger.debug("install rule for destination {}", destMac);
			try {
				sw.write(rule, null);
				logger.info("Rule installation successfull");
			} catch (Exception e) {
				logger.error("Rule installation failed");
				e.printStackTrace();
			}

			// push the packet to the switch
			this.pushPacket(sw, match, pi, outPort);
		}

		return Command.CONTINUE;
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

	private Command hubLogic(IOFSwitch sw, OFPacketIn pi, OFMatch match) {

		OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.PACKET_OUT);
		po.setBufferId(pi.getBufferId()).setInPort(pi.getInPort());

		// set actions
		OFActionOutput action = new OFActionOutput()
				.setPort((short) OFPort.OFPP_FLOOD.getValue());
		po.setActions(Collections.singletonList((OFAction) action));
		po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);

		// set data if is is included in the packetin
		if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
			byte[] packetData = pi.getPacketData();
			po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
					+ po.getActionsLength() + packetData.length));
			po.setPacketData(packetData);
		} else {
			po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
					+ po.getActionsLength()));
		}
		try {
			sw.write(po, null);
		} catch (IOException e) {
			logger.error("Failure writing PacketOut", e);
		}

		return Command.CONTINUE;
	}
}

