# Function to test specific service detection
function test_service_detection(port, expected_service) {
    service_key = "Services/" + expected_service;
    known_key = "Known/tcp/" + port;
    
    service_value = get_kb_item(service_key);
    known_value = get_kb_item(known_key);
    
    if (service_value) {
        display("Service detection successful for port " + port + ": " + expected_service);
        display("    Services/" + expected_service + " = " + service_value);
    } else {
        display("Service detection failed for port " + port + ": expected " + expected_service);
    }
    
    if (known_value) {
        display("    Known/tcp/" + port + " = " + known_value);
    }
    
    return service_value != NULL;
}

function setup_test_ports() {
    # Set up some common ports that should be detected by find_service
    set_kb_item(name:"Ports/tcp/21", value:1);     # FTP
    set_kb_item(name:"Ports/tcp/22", value:1);     # SSH
    set_kb_item(name:"Ports/tcp/23", value:1);     # Telnet
    set_kb_item(name:"Ports/tcp/25", value:1);     # SMTP
    set_kb_item(name:"Ports/tcp/80", value:1);     # HTTP
    set_kb_item(name:"Ports/tcp/110", value:1);    # POP3
    set_kb_item(name:"Ports/tcp/143", value:1);    # IMAP
    set_kb_item(name:"Ports/tcp/12345", value:1);  # NetBus (security test)
    
    display("Set up test ports in KB");
}

display("Target: " + get_host_ip());
setup_test_ports();
display("Running find_service...");
plugin_run_find_service();

test_service_detection(port: 21, expected_service: "ftp");
test_service_detection(port: 22, expected_service: "ssh");
test_service_detection(port: 23, expected_service: "telnet");
test_service_detection(port: 25, expected_service: "smtp");
test_service_detection(port: 80, expected_service: "www");
test_service_detection(port: 110, expected_service: "pop3");
test_service_detection(port: 143, expected_service: "imap");
test_service_detection(port: 12345, expected_service: "netbus");