"""
API routes for real-time sniffing controls.
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, List
import time
import asyncio

from ..sniffing.sniffer import SnifferService
from ..api.routes import detect_anomalies
from ..api.models import DetectionRequest, NetworkFlow, DetectionMethod
from ..api.firewall import register_malicious_ip

router = APIRouter()

# Global sniffer instance
sniffer = SnifferService()

@router.post("/sniffer/start")
async def start_sniffer(interface: str = None):
    """Start the packet sniffer."""
    if sniffer.is_running:
        return {"message": "Sniffer is already running"}
    
    try:
        sniffer.start(interface)
        return {"message": "Sniffer started", "interface": interface or "auto"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/sniffer/stop")
async def stop_sniffer():
    """Stop the packet sniffer."""
    sniffer.stop()
    return {"message": "Sniffer stopped"}

@router.get("/sniffer/status")
async def get_sniffer_status():
    """Get current status and stats."""
    return {
        "is_running": sniffer.is_running,
        "packets_captured": sniffer.stats["packets_captured"],
        "active_flows": sniffer.stats["active_flows"],
        "packets_dropped": sniffer.stats.get("packets_dropped", 0)
    }

@router.get("/sniffer/latest")
async def get_latest_traffic():
    """
    Get latest flows, classify them, and return results.
    This effectively polls for real-time updates.
    """
    raw_flows = sniffer.get_flows(timeout_seconds=2.0)
    
    if not raw_flows:
        return {"flows": []}
        
    # Convert to Pydantic models
    flow_objects = []
    
    for f in raw_flows:
        flow_objects.append(NetworkFlow(
            flow_duration=f['Flow Duration'],
            total_fwd_packets=f['Total Fwd Packets'],
            total_bwd_packets=f['Total Backward Packets'],
            flow_bytes_per_sec=f['Flow Bytes/s'],
            flow_packets_per_sec=f['Flow Packets/s'],
            fwd_packet_length_mean=f['Fwd Packet Length Mean'],
            bwd_packet_length_mean=f['Bwd Packet Length Mean'],
            flow_iat_mean=f['Flow IAT Mean'],
            fwd_iat_mean=f['Fwd IAT Mean'],
            bwd_iat_mean=f['Bwd IAT Mean'],
            fwd_psh_flags=f['Fwd PSH Flags'],
            syn_flag_count=f['SYN Flag Count'],
            ack_flag_count=f['ACK Flag Count'],
            packet_length_variance=f['Packet Length Variance'],
            average_packet_size=f['Average Packet Size']
        ))
        
    # Import rules
    from ..api.rules import check_rules, rules
        
    # Run detection
    try:
        merged_results = []
        
        # Optionally run ML detection
        ml_results = None
        if rules.use_ml_detection:
            try:
                request = DetectionRequest(flows=flow_objects, method=DetectionMethod.COMBINED)
                detection_result = await detect_anomalies(request)
                ml_results = detection_result.results
            except Exception as e:
                pass  # ML failed, continue with rule-based only
        
        for i, flow_meta in enumerate(raw_flows):
            # Get ML result if available
            ml_is_anomaly = False
            ml_score = 0.0
            ml_attack_type = None
            
            if ml_results and i < len(ml_results):
                ml_result = ml_results[i]
                ml_score = ml_result.score
                ml_attack_type = ml_result.attack_type
                # Only consider it an anomaly if:
                # 1. ML says it's an anomaly
                # 2. Score exceeds threshold
                # 3. Attack type is NOT 'Normal' (classifier confirmed it's an attack)
                if ml_result.is_anomaly and ml_score > rules.anomaly_score_threshold:
                    # Only flag as malicious if attack type indicates actual attack
                    if ml_attack_type and ml_attack_type not in ['Normal', 'BENIGN', 'normal', 'benign']:
                        ml_is_anomaly = True
                    else:
                        # It's classified as Normal, so don't flag it
                        ml_is_anomaly = False
            
            # Check rule-based detection
            rule_check = check_rules(flow_meta['src_ip'], {
                "total_fwd_packets": flow_meta['Total Fwd Packets'],
                "total_bwd_packets": flow_meta['Total Backward Packets'],
                "flow_bytes_per_sec": flow_meta['Flow Bytes/s'],
                "flow_duration": flow_meta['Flow Duration'],
                "dst_port": flow_meta['dst_port'],
                "syn_flag_count": flow_meta['SYN Flag Count']
            })
            
            # Combine results: is_anomaly if EITHER ML or rules flagged it
            is_anomaly = ml_is_anomaly or rule_check["is_anomaly"]
            
            # Determine attack type and severity
            if rule_check["is_anomaly"]:
                attack_type = rule_check["reason"]
                severity = rule_check["severity"]
            elif ml_is_anomaly:
                attack_type = ml_attack_type or "ML Detected"
                severity = "critical" if ml_score > 4 else "high" if ml_score > 3 else "medium"
            else:
                attack_type = None
                severity = "none"
            
            # Register malicious IPs automatically - but ONLY for real attacks
            # Don't register if attack type is Normal/Benign
            if is_anomaly and attack_type and attack_type not in ['Normal', 'BENIGN', 'normal', 'benign', None]:
                register_malicious_ip(
                    ip=flow_meta['src_ip'],
                    score=ml_score if ml_score > 0 else 3.0,
                    attack_type=attack_type
                )
            
            merged_results.append({
                "src_ip": flow_meta['src_ip'],
                "dst_ip": flow_meta['dst_ip'],
                "src_port": flow_meta['src_port'],
                "dst_port": flow_meta['dst_port'],
                "protocol": flow_meta['protocol'],
                "is_attack": is_anomaly,
                "score": ml_score,
                "attack_type": attack_type,
                "severity": severity,
                "detection_method": "rule" if rule_check["is_anomaly"] else ("ml" if ml_is_anomaly else "none"),
                "recommendation": "Block IP" if is_anomaly else "Monitor"
            })
            
        return {"flows": merged_results}
        
    except Exception as e:
        return {"error": str(e), "flows": []}
