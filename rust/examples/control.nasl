# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

function append(a, i, b) {
  a[i] = b;
  return a;
}

a = 1;
a++;
++a;
a = a * 2;
set_kb_item(name: "important/a", value: a);
for (i = 1; i < 5; i++)
  if (a % i == 0)
    display("result: " + (get_kb_item("important/a") + i));
  else
    display("nope");
b = 5;
while (b) {
  local_var c;
  c = (b -= 1);
  display(c);
}
b = append(a: b, i: 1, b: 42);
foreach d(b) 
  display(d);
d = 1;
repeat {
  d -= 1;
  display('hello '+ d); 
} until d == 0;
exit(d);
