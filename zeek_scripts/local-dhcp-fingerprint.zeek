##! local-dhcp-fingerprint.zeek
##!
##! Adds DHCP Option 60 (Vendor Class Identifier) and Option 55 (Parameter Request List)
##! to dhcp.log as new fields, so Home-IDS's MAC-rotation device re-identification
##! (src/core/device_matching.py, src/extractors/zeek_features.py's ingest()) has real
##! fingerprint data to correlate against when a device's MAC address itself changes --
##! e.g. iOS "Private Wi-Fi Address" / Android's per-network randomized MAC -- not just
##! when its IP changes.
##!
##! CAVEAT: written against the standard base/protocols/dhcp analyzer's dhcp_message
##! event and DHCP::Options record (stable since Zeek 4.0's DHCP analyzer rewrite), but
##! not verified against a live Zeek instance as part of this change. `zeekctl deploy`
##! validates scripts before restarting -- if this fails to load, it will report a clear
##! error and refuse to deploy rather than silently breaking anything else, so it is safe
##! to try. If `options$param_list`/`options$vendor_class` aren't populated on your Zeek
##! build, this script still loads fine and simply logs empty fields (Home-IDS's Python
##! side already treats a partial/absent fingerprint as "no data," not "mismatch" -- see
##! device_matching.py's dhcp_fingerprint_match()).
##!
##! Option 77 (User Class) is deliberately left out: it is not a consistently-named field
##! across Zeek's DHCP::Options record in every version, and Home-IDS's matching logic
##! already works fine on vendor_class + param_list alone (both required fields degrade
##! independently on the Python side).
##!
##! Deploy: copy this file into your Zeek site directory
##! ($(zeek-config --site_dir), typically /opt/zeek/share/zeek/site/ for a security:zeek
##! + zeekctl install), then add to local.zeek:
##!   @load ./local-dhcp-fingerprint.zeek
##! ...and `sudo /opt/zeek/bin/zeekctl deploy`.
##!
##! Verify: after a device does a fresh DHCP request/renewal,
##!   tail -f /var/log/zeek/current/dhcp.log | grep -o '"vendor_class":"[^"]*"'
##! should start printing non-empty values. Empty is expected for devices that simply
##! haven't done a fresh DHCP transaction since Zeek started (a stale/still-valid lease
##! doesn't re-send Option 60/55) -- give it time, or reconnect a device's Wi-Fi to force
##! a fresh DHCP handshake if you want to confirm quickly.

@load base/protocols/dhcp

redef record DHCP::Info += {
	vendor_class: string &log &optional;
	param_list: vector of count &log &optional;
};

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) &priority=5
	{
	if ( ! is_orig )
		return;

	if ( ! c?$dhcp )
		return;

	if ( options?$vendor_class )
		c$dhcp$vendor_class = options$vendor_class;

	if ( options?$param_list )
		c$dhcp$param_list = options$param_list;
	}
