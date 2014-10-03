package net.floodlightcontroller.mynewapp;

import java.util.List;
import java.util.Map;

import net.floodlightcontroller.mynewapp.MyNewApp.HostConnectionData;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class DeviceBlockResource extends ServerResource {
	@Get("json")
	public String getMacToBlock() {
		String macId = (String) getRequestAttributes().get("macId");
		MyNewAppService appService = (MyNewAppService) getContext()
				.getAttributes().get(MyNewAppService.class.getCanonicalName());
		List<Long> list = appService.getListToBlock();
		Map<Long, HostConnectionData> devices = appService.getHostStatusMap();

		long mac = 0;
		try {
			mac = Long.valueOf(macId);
		} catch (NumberFormatException ex) {
			return "{status: Not able to parse mac address}";
		}

		if (!devices.containsKey(mac)) {
			return "{status: Mac Address not present in the network}";
		}
		list.add(mac);
		return "{status: Request sent to block Mac Id" + macId + " }";
	}
}

