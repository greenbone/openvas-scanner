set_kb_item(name: "port", value: 1);
set_kb_item(name: "port", value: 2);
set_kb_item(name: "host", value: "a");
set_kb_item(name: "host", value: "b");

a = get_kb_item("port") + ":" + get_kb_item("host");
display(a);
