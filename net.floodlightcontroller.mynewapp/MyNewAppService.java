package net.floodlightcontroller.mynewapp;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.mynewapp.MyNewApp.HostConnectionData;

public interface MyNewAppService extends IFloodlightService {
	public ConcurrentMap<Long, HostViolationVector> getViolationData();

	public List<Long> getListToBlock();

	public Map<Long, HostConnectionData> getHostStatusMap();

}

