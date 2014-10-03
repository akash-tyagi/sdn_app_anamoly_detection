package net.floodlightcontroller.mynewapp;

import java.util.concurrent.ConcurrentMap;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class DeviceViolationsResource extends ServerResource {
	@Get("json")
	public ConcurrentMap<Long, HostViolationVector> retrieve() {
		MyNewAppService appService = (MyNewAppService) getContext()
				.getAttributes().get(MyNewAppService.class.getCanonicalName());
		ConcurrentMap<Long, HostViolationVector> data = appService
				.getViolationData();
		return data;
	}
}

