package net.floodlightcontroller.mynewapp;

import java.util.Map;

import net.floodlightcontroller.mynewapp.MyNewApp.HostConnectionData;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class DevicesStatusResource extends ServerResource {
	@Get("json")
	public Map<Long, HostConnectionData> deviceStatus() {
		MyNewAppService appService = (MyNewAppService) getContext()
				.getAttributes().get(MyNewAppService.class.getCanonicalName());
		Map<Long, HostConnectionData> map = appService.getHostStatusMap();
		return map;
	}
}

