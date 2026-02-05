plugin_run_openvas_tcp_scanner();

open = get_kb_item( "TCPScanner/OpenPortsNb" );
display( "Open Ports: " + open );

closed = get_kb_item( "TCPScanner/ClosedPortsNb" );
display( "Closed Ports: " + closed );

filtered = get_kb_item( "TCPScanner/FilteredPortsNb" );
display( "Filtered Ports: " + filtered );

rst = get_kb_item( "TCPScanner/RSTRateLimit" );
display( "RST Rate Limit: " + rst );

display();
display( "RTT Stats:");

display();
display( "open:");

mean_rtt = get_kb_item( "TCPScanner/open/MeanRTT");
display( "Mean RTT: " + mean_rtt );
mean_rtt1000 = get_kb_item( "TCPScanner/open/MeanRTT1000");
display( "Mean RTT (ms): " + mean_rtt1000 );
max_rtt = get_kb_item( "TCPScanner/open/MaxRTT");
display( "Max RTT: " + max_rtt );
max_rtt1000 = get_kb_item( "TCPScanner/open/MaxRTT1000");
display( "Max RTT (ms): " + max_rtt1000 );
sdrtt = get_kb_item( "TCPScanner/open/SDRTT");
display( "SD RTT: " + sdrtt );
sdrtt1000 = get_kb_item( "TCPScanner/open/SDRTT1000");
display( "SD RTT (ms): " + sdrtt1000 );
estimated_max_rtt = get_kb_item( "TCPScanner/open/EstimatedMaxRTT");
display( "Estimated Max RTT: " + estimated_max_rtt );
estimated_max_rtt1000 = get_kb_item( "TCPScanner/open/EstimatedMaxRTT1000");
display( "Estimated Max RTT (ms): " + estimated_max_rtt1000 );

display();
display( "closed:");
mean_rtt = get_kb_item( "TCPScanner/closed/MeanRTT");
display( "Mean RTT: " + mean_rtt );
mean_rtt1000 = get_kb_item( "TCPScanner/closed/MeanRTT1000");
display( "Mean RTT (ms): " + mean_rtt1000 );
max_rtt = get_kb_item( "TCPScanner/closed/MaxRTT");
display( "Max RTT: " + max_rtt );
max_rtt1000 = get_kb_item( "TCPScanner/closed/MaxRT1000");
display( "Max RTT (ms): " + max_rtt1000 );
sdrtt = get_kb_item( "TCPScanner/closed/SDRTT");
display( "SD RTT: " + sdrtt );
sdrtt1000 = get_kb_item( "TCPScanner/closed/SDRTT1000");
display( "SD RTT (ms): " + sdrtt1000 );
estimated_max_rtt = get_kb_item( "TCPScanner/closed/EstimatedMaxRTT");
display( "Estimated Max RTT: " + estimated_max_rtt );
estimated_max_rtt1000 = get_kb_item( "TCPScanner/closed/EstimatedMaxRTT1000");
display( "Estimated Max RTT (ms): " + estimated_max_rtt1000 );

display();
display( "unfiltered:");
mean_rtt = get_kb_item( "TCPScanner/unfiltered/MeanRTT");
display( "Mean RTT: " + mean_rtt );
mean_rtt1000 = get_kb_item( "TCPScanner/unfiltered/MeanRTT1000");
display( "Mean RTT (ms): " + mean_rtt1000 );
max_rtt = get_kb_item( "TCPScanner/unfiltered/MaxRTT");
display( "Max RTT: " + max_rtt );
max_rtt1000 = get_kb_item( "TCPScanner/unfiltered/MaxRTT1000");
display( "Max RTT (ms): " + max_rtt1000 );
sdrtt = get_kb_item( "TCPScanner/unfiltered/SDRTT");
display( "SD RTT: " + sdrtt );
sdrtt1000 = get_kb_item( "TCPScanner/unfiltered/SDRTT1000");
display( "SD RTT (ms): " + sdrtt1000 );
estimated_max_rtt = get_kb_item( "TCPScanner/unfiltered/EstimatedMaxRTT");
display( "Estimated Max RTT: " + estimated_max_rtt );
estimated_max_rtt1000 = get_kb_item( "TCPScanner/unfiltered/EstimatedMaxRTT1000");
display( "Estimated Max RTT (ms): " + estimated_max_rtt1000 );

for (port = 0; port < 65536; port++) {
    banner = get_kb_item( "Banner/" + port );
    if( banner ) {
        display();
        display( "Port: " + port );
        display( "Banner: " + banner );
    } else {
        continue;
    }

    rw_time = get_kb_item( "TCPScanner/RwTime/" + port);
    display( "RW Time: " + rw_time );

    rw_time1000 = get_kb_item( "TCPScanner/RwTime1000/" + port);
    display( "RW Time (ms): " + rw_time1000 );

    cnx_time = get_kb_item( "TCPScanner/CnxTime/" + port);
    display( "Connection Time: " + cnx_time );

    cnx_time1000 = get_kb_item( "TCPScanner/CnxTime1000/" + port);
    display( "Connection Time (ms): " + cnx_time1000 );
    
}
