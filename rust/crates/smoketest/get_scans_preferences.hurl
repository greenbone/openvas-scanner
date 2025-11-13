GET {{server}}/scans/preferences
HTTP 200
[Asserts]
jsonpath "$[0].id" == "auto_enable_dependencies"
jsonpath "$[0].name" == "Automatic Enable Dependencies"
jsonpath "$[0].default" == true
jsonpath "$[0].description" == "OpenVAS plugins use the result of each other to execute their job. For instance, a plugin which logs into the remote SMB registry will need the results of the plugin which finds the SMB name of the remote host and the results of the plugin which attempts to log into the remote host. If you want to only select a subset of the plugins available, tracking the dependencies can quickly become tiresome. If you set this option to 'yes', openvas will automatically enable the plugins that are depended on."

jsonpath "$[6].id" == "optimize_test"
jsonpath "$[6].name" == "Optimize Test"
jsonpath "$[6].default" == true
jsonpath "$[6].description" == "By default, optimize_test is enabled which means openvas does trust the remote host banners and is only launching plugins against the services they have been designed to check. For example it will check a web server claiming to be IIS only for IIS related flaws but will skip plugins testing for Apache flaws, and so on. This default behavior is used to optimize the scanning performance and to avoid false positives. If you are not sure that the banners of the remote host have been tampered with, you can disable this option."

jsonpath "$[7].id" == "plugins_timeout"
jsonpath "$[7].name" == "Plugins Timeout"
jsonpath "$[7].default" == 320
jsonpath "$[7].description" == 	"This is the maximum lifetime, in seconds of a plugin. It may happen that some plugins are slow because of the way they are written or the way the remote server behaves. This option allows you to make sure your scan is never caught in an endless loop because of a non-finishing plugin. Doesn't affect ACT_SCANNER plugins, use 'ACT_SCANNER plugins timeout' for them instead."

jsonpath "$[22].id" == "max_mem_kb"
jsonpath "$[22].name" == "Maximum Script KB Memory"
jsonpath "$[22].default" == 0
jsonpath "$[22].description" == "Maximum amount of memory (in MB) allowed to use for a single script. If this value is set, the amount of memory put into redis is tracked for every Script. If the amount of memory exceeds this limit, the script is not able to set more kb items. The tracked the value written into redis is only estimated, as it does not check, if a value was replaced or appended. The size of the key is also not tracked. If this value is not set or <= 0, the maximum amount is unlimited (Default)."
