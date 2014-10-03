package net.floodlightcontroller.mynewapp;

import java.util.List;
import java.util.Map;

import net.floodlightcontroller.mynewapp.MyNewApp.HostConnectionData;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class DeviceUnblockResource extends ServerResource {
	@Get("json")
	public String getHostToUnBlock() {
		String macId = (String) getRequestAttributes().get("macId");
		MyNewAppService appService = (MyNewAppService) getContext()
				.getAttributes().get(MyNewAppService.class.getCanonicalName());
		List<Long> list = appService.getListToBlock();
		Map<Long, HostConnectionData> hosts = appService.getHostStatusMap();

		long mac = 0;
		try {
			mac = Long.valueOf(macId);
		} catch (NumberFormatException ex) {
			return "{status: Not able to parse mac address}";
		}

		if (!hosts.containsKey(mac)) {
			return "{status: Mac Address not present in the network}";
		}
		list.remove(mac);
		hosts.get(mac).status = HostConnectionData.HOST_STATUS_CONNECTED;
		return "{status: Request sent to unblock Host with Mac Address" + macId
				+ " }";
	}
}

