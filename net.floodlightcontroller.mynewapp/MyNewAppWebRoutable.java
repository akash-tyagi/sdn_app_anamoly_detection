package net.floodlightcontroller.mynewapp;

import net.floodlightcontroller.restserver.RestletRoutable;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

public class MyNewAppWebRoutable implements RestletRoutable {

	@Override
	public Restlet getRestlet(Context context) {
		Router router = new Router(context);
		router.attach("/devices/violations", DeviceViolationsResource.class);
		router.attach("/devices/{macId}/block", DeviceBlockResource.class);
		router.attach("/devices/{macId}/unblock", DeviceUnblockResource.class);
		router.attach("/devices/list", DevicesStatusResource.class);
		return router;
	}

	@Override
	public String basePath() {
		return "/wm/mynewapp";
	}

}

