from fastapi import FastAPI, Query
import nmap  # Python wrapper for Nmap
import subprocess
from typing import Optional

app = FastAPI(title="MCP Nmap Server", version="1.0.0")

# Initialize Nmap Scanner
nm = nmap.PortScanner()

@app.get("/")
def root():
    return {"status": "MCP Nmap Server is running"}

@app.get("/scan")
def run_scan(
    target: str = Query(..., description="Target(s): IP, domain, CIDR, or space/comma-separated list"),
    ports: Optional[str] = Query(None, description="Ports, e.g. 22,80,443 or 1-1024"),
    arguments: Optional[str] = Query(None, description="Raw nmap arguments string to pass through (advanced)"),
    service_version: bool = Query(False, description="-sV: Version detection"),
    os_detection: bool = Query(False, description="-O: OS detection"),
    aggressive: bool = Query(False, description="-A: Aggressive scan (OS, version, script, traceroute)"),
    udp: bool = Query(False, description="-sU: UDP scan"),
    no_ping: bool = Query(False, description="-Pn: Skip host discovery"),
    timing_template: Optional[int] = Query(None, ge=0, le=5, description="-T<0-5>: Timing template"),
    top_ports: Optional[int] = Query(None, ge=1, description="--top-ports <N>"),
    scripts: Optional[str] = Query(None, description="--script <name>[,<name2>] or category"),
    min_rate: Optional[int] = Query(None, ge=1, description="--min-rate <pps>"),
    max_rate: Optional[int] = Query(None, ge=1, description="--max-rate <pps>"),
    max_retries: Optional[int] = Query(None, ge=0, description="--max-retries <tries>"),
    dns_servers: Optional[str] = Query(None, description="--dns-servers <server[,server2,...]>"),
    interface: Optional[str] = Query(None, description="-e <iface>: Network interface to use"),
    source_port: Optional[int] = Query(None, ge=1, le=65535, description="-g/--source-port <port>"),
    ipv6: bool = Query(False, description="-6: Enable IPv6 scanning"),
    verbose: Optional[int] = Query(None, ge=1, le=2, description="-v or -vv: Verbosity level"),
):
    """
    Run an Nmap scan on the target with given ports.
    Example: /scan?target=scanme.nmap.org&ports=22,80,443
    """
    try:
        # Build nmap arguments
        args = []
        if arguments:
            args.append(arguments)
        if service_version:
            args.append("-sV")
        if os_detection:
            args.append("-O")
        if aggressive:
            args.append("-A")
        if udp:
            args.append("-sU")
        if no_ping:
            args.append("-Pn")
        if timing_template is not None:
            args.append(f"-T{timing_template}")
        if verbose is not None:
            args.append("-" + "v" * verbose)
        if top_ports is not None:
            args.append(f"--top-ports {top_ports}")
        if scripts:
            args.append(f"--script {scripts}")
        if min_rate is not None:
            args.append(f"--min-rate {min_rate}")
        if max_rate is not None:
            args.append(f"--max-rate {max_rate}")
        if max_retries is not None:
            args.append(f"--max-retries {max_retries}")
        if dns_servers:
            args.append(f"--dns-servers {dns_servers}")
        if interface:
            args.append(f"-e {interface}")
        if source_port is not None:
            args.append(f"-g {source_port}")
        if ipv6:
            args.append("-6")
        # Ports handling (avoid conflict if top_ports specified)
        if ports and not top_ports:
            args.append(f"-p {ports}")

        final_args = " ".join(a for a in args if a)

        # Execute scan using arguments string
        nm.scan(hosts=target, arguments=final_args)

        all_hosts = nm.all_hosts()
        scaninfo = nm.scaninfo()
        cmdline = getattr(nm, "command_line", lambda: None)()

        # If the exact target key isn't present, avoid KeyError and provide context
        if target in all_hosts:
            results = nm[target]
            return {
                "target": target,
                "ports": ports,
                "hosts": all_hosts,
                "scaninfo": scaninfo,
                "scan_result": results,
                "command_line": cmdline,
                "arguments": final_args,
            }
        elif all_hosts:
            # Return results for all discovered hosts
            aggregated = {host: nm[host] for host in all_hosts}
            return {
                "target": target,
                "ports": ports,
                "hosts": all_hosts,
                "scaninfo": scaninfo,
                "scan_result": aggregated,
                "command_line": cmdline,
                "arguments": final_args,
                "message": "Target not found in results; returning discovered hosts."
            }
        else:
            return {
                "target": target,
                "ports": ports,
                "hosts": all_hosts,
                "scaninfo": scaninfo,
                "command_line": cmdline,
                "arguments": final_args,
                "error": "No hosts found. Check DNS/target reachability, privileges, or port range.",
            }
    except nmap.PortScannerError as e:
        return {"error": f"Nmap error: {e}", "target": target, "ports": ports}
    except Exception as e:
        return {"error": str(e)}

@app.get("/version")
def get_nmap_version():
    """Return the Nmap version installed on the server"""
    try:
        version = subprocess.check_output(["nmap", "--version"]).decode("utf-8").split("\n")[0]
        return {"nmap_version": version}
    except Exception as e:
        return {"error": str(e)}
