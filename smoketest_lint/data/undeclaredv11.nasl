# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

barlist2 = get_kb_list( "bar/foo" );
foreach bar3( barlist2 ) {#!none
  bar4 = bar3;
  if( bar4 ) {}
}


foolist = get_kb_list( "foo/bar");
foo = foolist[1];


barlist = get_kb_list( "bar/foo" );
foreach bar( barlist ) {
  bar2 = bar;
  if( bar2 ) {}
}


foonull = NULL;
fooempty = "";
if( foonull ){}
if( fooempty ){}


fooempty3 += "";
foonull3 += NULL;
if( fooempty3 ){}
if( foonull3 ){}


fooincrement++;
if( fooincrement++ ){}


foostring += string("foo");
if( foostring ) {}


if(!get_port_state(foostateport)){}
#!undeclared:foostateport


function foreachfunc(foreachport) {
  local_var foreachport, foreachports;
  foreachports = make_list(123,456);
  foreach foreachport( foreachports ) {}
}
foreachprot = 123;
foreachfunc(foreachport:foreachport);
#!undeclared:foreachport


fooarraythere['1'] = 2;
if(fooarraynotthere[0]) {}
#!undeclared:fooarraynotthere


foo = toupper(fooarraynotthere2["foo"]);
#!undeclared:fooarraynotthere2


function fooFunc(foo) {
  local_var foo;
}
if(!fooFunc(foo:foofile)){}
#!undeclared:foofile


function fooPort( _fooport ) {
  local_var fooport;
  fooport = _fooport;
}
fooPort();
log_message(port:fooport);
#!undeclared:fooport


display(displaybar);
#!undeclared:displaybar
displaybar = 0;


foreach bar3( barlist3 ) {}
#!undeclared:barlist3


foonull = NULL;
fooempty = "";
if( foonull2 ){}
#!undeclared:foonull2
if( fooempty2 ){}
#!undeclared:fooempty2