"""
Background service for packet sniffing and flow aggregation.
"""
import threading
import time
import queue
from scapy.all import sniff, IP
from typing import List, Dict
from pathlib import Path

from .feature_extractor import FeatureExtractor
from ..utils.logger import get_logger

logger = get_logger(__name__)

# Memory limits to prevent crashes under heavy traffic
MAX_QUEUE_SIZE = 10000  # Maximum packets in queue before dropping
MAX_ACTIVE_FLOWS = 5000  # Maximum concurrent flows to track
MAX_PACKETS_PER_FLOW = 1000  # Maximum packets per individual flow


class SnifferService:
    def __init__(self):
        self.is_running = False
        self.sniffer_thread = None
        # Use bounded queue to prevent memory exhaustion
        self.packet_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.feature_extractor = FeatureExtractor(max_packets_per_flow=MAX_PACKETS_PER_FLOW)
        self.stats = {
            "packets_captured": 0,
            "active_flows": 0,
            "packets_dropped": 0
        }
        self.stop_event = threading.Event()
        self.ignored_ip = None

    def start(self, interface: str = None, exclude_local: bool = True):
        """Start the sniffing service."""
        if self.is_running:
            return
            
        self.is_running = True
        self.stop_event.clear()
        
        # Determine local IP to exclude
        if exclude_local:
            try:
                from scapy.all import get_if_addr, conf
                iface = interface or conf.iface
                self.ignored_ip = get_if_addr(iface)
                logger.info(f"Excluding traffic from local IP: {self.ignored_ip}")
            except Exception as e:
                logger.warning(f"Could not determine local IP: {e}")
                self.ignored_ip = None
        else:
            self.ignored_ip = None
        
        # Start packet processing thread
        threading.Thread(target=self._process_packets, daemon=True).start()
        
        # Start sniffing thread
        self.sniffer_thread = threading.Thread(
            target=self._sniff_loop,
            args=(interface,),
            daemon=True
        )
        self.sniffer_thread.start()
        logger.info(f"Sniffer started on interface: {interface or 'default'}")

    def stop(self):
        """Stop the sniffing service."""
        self.is_running = False
        self.stop_event.set()
        logger.info("Sniffer stopped")

    def _sniff_loop(self, interface):
        """Main Scapy sniffing loop."""
        try:
            def safe_enqueue(pkt):
                """Safely add packet to queue, dropping if full."""
                try:
                    self.packet_queue.put_nowait(pkt)
                except queue.Full:
                    # Queue is full, drop packet to prevent memory issues
                    self.stats["packets_dropped"] += 1
                    
            # Filter for IP traffic only
            sniff(
                iface=interface,
                prn=safe_enqueue,
                store=False,
                stop_filter=lambda x: not self.is_running,
                filter="ip"
            )
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
            self.is_running = False

    def _process_packets(self):
        """Process queued packets into flows."""
        cleanup_counter = 0
        
        while self.is_running or not self.packet_queue.empty():
            try:
                pkt = self.packet_queue.get(timeout=1.0)
                
                # Filter excluded IP
                if self.ignored_ip and IP in pkt:
                    if pkt[IP].src == self.ignored_ip:
                        continue
                
                # Check if we're at flow limit before adding more
                if len(self.feature_extractor.active_flows) >= MAX_ACTIVE_FLOWS:
                    # Force cleanup of old flows
                    self._cleanup_old_flows(force=True)
                        
                self.feature_extractor.process_packet(pkt)
                self.stats["packets_captured"] += 1
                self.stats["active_flows"] = len(self.feature_extractor.active_flows)
                
                # Periodic cleanup every 1000 packets
                cleanup_counter += 1
                if cleanup_counter >= 1000:
                    self._cleanup_old_flows()
                    cleanup_counter = 0
                    
            except queue.Empty:
                # Good time to do cleanup when idle
                self._cleanup_old_flows()
                continue
            except Exception as e:
                logger.error(f"Processing error: {e}")
    
    def _cleanup_old_flows(self, force: bool = False):
        """Clean up stale flows to free memory."""
        current_time = time.time()
        keys_to_remove = []
        
        for key, packets in list(self.feature_extractor.active_flows.items()):
            if not packets:
                keys_to_remove.append(key)
                continue
            
            last_time = packets[-1].time
            
            # Remove flows that haven't had activity for 30 seconds
            # or if force cleanup (at limit), remove flows older than 10 seconds
            timeout = 10 if force else 30
            if (current_time - last_time) > timeout:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            if key in self.feature_extractor.active_flows:
                del self.feature_extractor.active_flows[key]
            if key in self.feature_extractor.flow_start_times:
                del self.feature_extractor.flow_start_times[key]
            if key in self.feature_extractor.flow_last_packet_time:
                del self.feature_extractor.flow_last_packet_time[key]

    def get_flows(self, timeout_seconds=5.0) -> List[Dict]:
        """
        Get completed flows or flows active longer than timeout.
        Returns list of feature dictionaries ready for model.
        """
        current_time = time.time()
        ready_flows = []
        
        # Convert timestamp keys to list to avoid runtime error during iteration
        keys = list(self.feature_extractor.active_flows.keys())
        
        for key in keys:
            packets = self.feature_extractor.active_flows[key]
            if not packets:
                continue
                
            start_time = packets[0].time
            last_time = packets[-1].time
            duration = last_time - start_time
            
            # If flow is long enough or hasn't updated recently, process it
            if duration > timeout_seconds or (current_time - last_time) > 2.0:
                features = self.feature_extractor.extract_features(key, packets)
                if features:
                    ready_flows.append(features)
                
                # Reset/Remove processed flows to prevent infinite growth
                del self.feature_extractor.active_flows[key]
                if key in self.feature_extractor.flow_start_times:
                    del self.feature_extractor.flow_start_times[key]
        
        return ready_flows
