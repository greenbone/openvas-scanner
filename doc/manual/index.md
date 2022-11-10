# Introduction

## GENERAL

This documentation is meant to get the new standard for the OpenVAS documentation. It will contain general information about different parts of the project, as well as a technical description of the language NASL with its grammar and library functions. In the current state this documentation is far from complete and will fill up by time.

## SUMMARY

OpenVAS is a project containing several parts and programs. In general there are two main parts: the OpenVAS Scanner and NASL. The OpenVAS Scanner is more like an engine consisting of a scan management part, which manages different hosts and plugins. Plugins are scripts, interpreted by the NASL interpreter. There is also a standalone program, which allows to run NASL scripts directly without having a running scan.

To run a scan additional programs are needed. Currently the best way is to use the [Greenbone Vulnerability Manager](https://github.com/greenbone/gvmd), [Greenbone Security Assistant](https://github.com/greenbone/gsa)/[Greenbone Security Assistant HTTP server](https://github.com/greenbone/gsad) and [OSPD-OpenVAS](https://github.com/greenbone/ospd-openvas)

## SEE ALSO

**[openvas](openvas/index.md)**, **[NASL](nasl/index.md)**