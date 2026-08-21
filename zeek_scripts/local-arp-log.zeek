##! local-arp-log.zeek
##!
##! Writes a new arp.log from the low-level arp_request/arp_reply events, which
##! Home-IDS's Phase 21B ARP host-discovery-sweep detector
##! (src/extractors/zeek_features.py's ingest(), "arp" branch) reads for spa/tpa/
##! operation fields.
##!
##! Why this script exists: confirmed via live testing against a real deployed Zeek
##! 8.0.8 instance (with zeek/foxio/ja4 and zeek/salesforce/ja3 installed) that stock
##! Zeek ships the low-level arp_request/arp_reply/bad_arp EVENTS
##! (base/bif/plugins/Zeek_ARP.events.bif.zeek) but, unlike conn/dns/http/ssl, no
##! base/protocols/arp module that actually writes an arp.log -- an earlier version of
##! the ARP-sweep detector's own code comments only guessed arp.log existed by
##! default; it does not. Also confirmed live: arp_request/arp_reply themselves DO
##! fire correctly for real ARP traffic with no logging script loaded at all (verified
##! against a real captured WiFi burst: 71 requests / 71 replies, correct SPA/TPA/MAC
##! data) -- the analyzer works fine, only the logging step was missing. This script
##! adds just that.
##!
##! Deploy: copy into your Zeek site directory ($(zeek-config --site_dir), typically
##! /opt/zeek/share/zeek/site/ for a security:zeek + zeekctl install), then add to
##! local.zeek:
##!   @load ./local-arp-log.zeek
##! ...and `sudo /opt/zeek/bin/zeekctl deploy`.
##!
##! Verify: ARP is broadcast, so this should populate quickly on any active LAN/WLAN
##! segment:
##!   tail -f /opt/zeek/logs/current/arp.log | grep -o '"operation":"[^"]*"'

module ARP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:        time    &log;
		mac_src:   string  &log;
		mac_dst:   string  &log;
		spa:       addr    &log;
		tpa:       addr    &log;
		operation: string  &log;
	};
}

event zeek_init() &priority=5
	{
	Log::create_stream(ARP::LOG, [$columns=Info, $path="arp"]);
	}

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
	{
	local rec: Info = [$ts=network_time(), $mac_src=mac_src, $mac_dst=mac_dst,
	                    $spa=SPA, $tpa=TPA, $operation="REQUEST"];
	Log::write(ARP::LOG, rec);
	}

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
	{
	local rec: Info = [$ts=network_time(), $mac_src=mac_src, $mac_dst=mac_dst,
	                    $spa=SPA, $tpa=TPA, $operation="REPLY"];
	Log::write(ARP::LOG, rec);
	}
